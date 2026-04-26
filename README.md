# ITGC PII Shield

Browser-based Excel PII masking and encrypted file handling.

## Features
- Upload `.xlsx`
- Mask high-confidence PII only
- Preserve operational/business columns
- Encrypt masked workbook with Fernet
- Decrypt `.enc` files in the browser via the web UI
- Audit log of operations

## Local run
```bash
pip install -r requirements.txt
python app.py
```

Open `http://localhost:5000`

## Docker
```bash
docker build -t itgc-pii-shield .
docker run -p 8080:8080 -e PORT=8080 itgc-pii-shield
```

## Notes
- Only `.xlsx` is supported for masking because formatting preservation is much safer than converting legacy `.xls`.
- Decryption is done by uploading the `.enc` file to the website and entering the password/key in the browser.
