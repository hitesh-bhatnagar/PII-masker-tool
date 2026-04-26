"""
Encryption helpers for the ITGC PII Shield tool.

Format:
- New files begin with a small magic header so the decryptor can identify the format.
- The payload contains a mode byte, a 16-byte salt field, and a Fernet ciphertext.
- Password mode derives a key from the password + salt.
- Key mode uses the supplied Fernet key directly.
"""

from __future__ import annotations

import base64
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

MAGIC = b"ITGCPII1"
MODE_PASSWORD = b"P"
MODE_KEY = b"K"
SALT_LEN = 16


def generate_key() -> bytes:
    return Fernet.generate_key()


def derive_key_from_password(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480_000,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode("utf-8")))


def _is_valid_fernet_key(candidate: str) -> bool:
    try:
        raw = candidate.encode("utf-8")
        Fernet(raw)
        return True
    except Exception:
        return False


def encrypt_file(input_path: str, output_path: str, password: str | None = None) -> dict:
    """
    Encrypt a file with Fernet.
    If password is provided, the key is derived from that password.
    Otherwise a random Fernet key is generated and returned to the caller once.
    """
    with open(input_path, "rb") as f:
        plaintext = f.read()

    if password:
        salt = os.urandom(SALT_LEN)
        key = derive_key_from_password(password, salt)
        mode = MODE_PASSWORD
        secret_for_user = None
    else:
        salt = b"\x00" * SALT_LEN
        key = generate_key()
        mode = MODE_KEY
        secret_for_user = key.decode("utf-8")

    token = Fernet(key).encrypt(plaintext)
    payload = MAGIC + mode + salt + token

    with open(output_path, "wb") as f:
        f.write(payload)

    result = {
        "encrypted_path": output_path,
        "original_size_kb": round(len(plaintext) / 1024, 2),
        "encrypted_size_kb": round(len(payload) / 1024, 2),
        "salt": base64.urlsafe_b64encode(salt).decode("utf-8") if password else None,
        "key": secret_for_user,
        "mode": "password" if password else "generated_key",
    }
    return result


def decrypt_file(encrypted_path: str, output_path: str, secret: str, mode: Literal["password", "key"] = "password") -> tuple[bool, str]:
    """
    Decrypt an encrypted file created by encrypt_file().
    mode="password" means `secret` is a human password.
    mode="key" means `secret` is a Fernet key.
    """
    try:
        with open(encrypted_path, "rb") as f:
            payload = f.read()

        key: bytes
        ciphertext: bytes

        if payload.startswith(MAGIC):
            file_mode = payload[len(MAGIC):len(MAGIC) + 1]
            salt = payload[len(MAGIC) + 1:len(MAGIC) + 1 + SALT_LEN]
            ciphertext = payload[len(MAGIC) + 1 + SALT_LEN:]

            if file_mode == MODE_PASSWORD:
                if mode == "key" and _is_valid_fernet_key(secret):
                    # If the user accidentally pastes a key, still allow it.
                    key = secret.encode("utf-8")
                else:
                    key = derive_key_from_password(secret, salt)
            elif file_mode == MODE_KEY:
                if not _is_valid_fernet_key(secret):
                    return False, "This file expects a Fernet key, not a password."
                key = secret.encode("utf-8")
            else:
                return False, "Unknown encrypted file format."
        else:
            # Legacy fallback support:
            # - password-based legacy payloads were salt + ciphertext
            # - key-based legacy payloads were raw Fernet ciphertext
            if mode == "password":
                if len(payload) < SALT_LEN:
                    return False, "Invalid encrypted file."
                salt = payload[:SALT_LEN]
                ciphertext = payload[SALT_LEN:]
                key = derive_key_from_password(secret, salt)
            else:
                if not _is_valid_fernet_key(secret):
                    return False, "Invalid Fernet key."
                ciphertext = payload
                key = secret.encode("utf-8")

        decrypted = Fernet(key).decrypt(ciphertext)

        with open(output_path, "wb") as f:
            f.write(decrypted)

        return True, "Decryption successful"
    except InvalidToken:
        return False, "Invalid password/key or corrupted .enc file"
    except Exception as e:
        return False, f"Decryption failed: {e}"
