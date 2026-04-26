"""
ITGC PII Shield
Flask backend for:
- Uploading Excel files
- Masking PII in worksheets
- Encrypting masked output
- Decrypting .enc files in-browser via API
"""

from __future__ import annotations

import json
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path

from flask import Flask, jsonify, render_template, request, send_file
from werkzeug.utils import secure_filename

from excel_processor import process_excel
from encryptor import decrypt_file, encrypt_file

BASE_DIR = Path(__file__).resolve().parent
UPLOAD_DIR = BASE_DIR / "uploads"
OUTPUT_DIR = BASE_DIR / "outputs"
AUDIT_LOG = BASE_DIR / "audit_log.jsonl"
ALLOWED_INPUT_EXTENSIONS = {".xlsx"}
ALLOWED_ENC_EXTENSIONS = {".enc"}

MAX_CONTENT_LENGTH = 50 * 1024 * 1024  # 50 MB


def ensure_dirs() -> None:
    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)


ensure_dirs()

app = Flask(__name__, template_folder="templates", static_folder="static")
app.config["MAX_CONTENT_LENGTH"] = MAX_CONTENT_LENGTH


def allowed_input_file(filename: str) -> bool:
    return Path(filename).suffix.lower() in ALLOWED_INPUT_EXTENSIONS


def allowed_enc_file(filename: str) -> bool:
    return Path(filename).suffix.lower() in ALLOWED_ENC_EXTENSIONS


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def write_audit(entry: dict) -> None:
    entry["timestamp"] = utc_now()
    with open(AUDIT_LOG, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry, ensure_ascii=False) + "\n")


@app.get("/")
def index():
    return render_template("index.html")


@app.post("/api/process")
def process():
    uploaded = request.files.get("file")
    if uploaded is None:
        return jsonify({"error": "No file uploaded"}), 400

    if not uploaded.filename:
        return jsonify({"error": "Empty filename"}), 400

    if not allowed_input_file(uploaded.filename):
        return jsonify({"error": "Only .xlsx files are supported"}), 400

    password = request.form.get("password", "").strip() or None
    highlight_masked = request.form.get("highlight_masked", "true").lower() != "false"
    audit_ref = request.form.get("reference", "").strip()

    job_id = str(uuid.uuid4())[:8]
    original_name = secure_filename(uploaded.filename)
    stem = Path(original_name).stem

    upload_path = UPLOAD_DIR / f"{job_id}_{original_name}"
    masked_path = OUTPUT_DIR / f"{job_id}_{stem}_masked.xlsx"
    enc_path = OUTPUT_DIR / f"{job_id}_{stem}_masked.enc"

    uploaded.save(upload_path)

    report = process_excel(
        input_path=str(upload_path),
        output_path=str(masked_path),
        highlight_masked=highlight_masked,
    )

    if report["errors"]:
        write_audit({
            "job_id": job_id,
            "action": "process",
            "status": "error",
            "file": original_name,
            "errors": report["errors"],
            "reference": audit_ref or None,
        })
        return jsonify({"error": report["errors"][0]}), 500

    enc_result = encrypt_file(
        input_path=str(masked_path),
        output_path=str(enc_path),
        password=password,
    )

    write_audit({
        "job_id": job_id,
        "action": "process",
        "status": "success",
        "file": original_name,
        "reference": audit_ref or None,
        "sheets": report["sheets_processed"],
        "total_cells_scanned": report["total_cells_scanned"],
        "total_pii_masked": report["total_pii_masked"],
        "pii_breakdown": report["pii_breakdown"],
        "encryption_mode": "password" if password else "generated_key",
        "password_protected": bool(password),
    })

    try:
        upload_path.unlink(missing_ok=True)
    except Exception:
        pass

    response = {
        "job_id": job_id,
        "report": report,
        "encryption": {
            "mode": "password" if password else "generated_key",
            "salt": enc_result.get("salt"),
            "original_size_kb": enc_result["original_size_kb"],
            "encrypted_size_kb": enc_result["encrypted_size_kb"],
            "download_name": Path(enc_result["encrypted_path"]).name,
        },
        "download_token": job_id,
    }

    if not password:
        response["encryption"]["key"] = enc_result["key"]
        response["encryption"]["key_warning"] = "Save this key now; it is not stored on the server."

    return jsonify(response)


@app.post("/api/decrypt")
def decrypt():
    uploaded = request.files.get("file")
    if uploaded is None:
        return jsonify({"error": "No encrypted file uploaded"}), 400

    if not uploaded.filename:
        return jsonify({"error": "Empty filename"}), 400

    if not allowed_enc_file(uploaded.filename):
        return jsonify({"error": "Only .enc files are supported"}), 400

    secret = request.form.get("secret", "").strip()
    mode = request.form.get("mode", "password").strip().lower()
    if not secret:
        return jsonify({"error": "Please provide a password or key"}), 400
    if mode not in {"password", "key"}:
        return jsonify({"error": "Invalid decrypt mode"}), 400

    job_id = str(uuid.uuid4())[:8]
    original_name = secure_filename(uploaded.filename)
    stem = Path(original_name).stem

    upload_path = UPLOAD_DIR / f"{job_id}_{original_name}"
    output_path = OUTPUT_DIR / f"{job_id}_{stem}_decrypted.xlsx"

    uploaded.save(upload_path)

    ok, message = decrypt_file(
        encrypted_path=str(upload_path),
        output_path=str(output_path),
        secret=secret,
        mode=mode,
    )

    if not ok:
        write_audit({
            "job_id": job_id,
            "action": "decrypt",
            "status": "error",
            "file": original_name,
        })
        try:
            upload_path.unlink(missing_ok=True)
        except Exception:
            pass
        return jsonify({"error": message or "Decryption failed"}), 400

    write_audit({
        "job_id": job_id,
        "action": "decrypt",
        "status": "success",
        "file": original_name,
        "mode": mode,
    })

    try:
        upload_path.unlink(missing_ok=True)
    except Exception:
        pass

    return send_file(
        output_path,
        as_attachment=True,
        download_name=output_path.name,
        mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    )


@app.get("/api/download/<job_id>/<file_type>")
def download(job_id: str, file_type: str):
    if not job_id.replace("-", "").replace("_", "").isalnum():
        return jsonify({"error": "Invalid token"}), 400

    if file_type == "masked":
        candidates = [
            f for f in OUTPUT_DIR.iterdir()
            if f.name.startswith(f"{job_id}_") and f.name.endswith("_masked.xlsx")
        ]
    elif file_type == "encrypted":
        candidates = [
            f for f in OUTPUT_DIR.iterdir()
            if f.name.startswith(f"{job_id}_") and f.name.endswith(".enc")
        ]
    else:
        return jsonify({"error": "Invalid file type"}), 400

    if not candidates:
        return jsonify({"error": "File not found"}), 404

    path = candidates[0]
    return send_file(path, as_attachment=True, download_name=path.name)


@app.get("/api/audit")
def audit():
    logs = []
    try:
        with open(AUDIT_LOG, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    logs.append(json.loads(line))
    except FileNotFoundError:
        pass
    return jsonify({"logs": logs[-50:]})


if __name__ == "__main__":
    app.run(debug=False, host="0.0.0.0", port=int(os.environ.get("PORT", "5000")))
