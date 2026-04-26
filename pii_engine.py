"""
PII detection and masking engine.

Goals:
- High-confidence masking of actual PII
- Avoid masking operational HR/business reference columns such as employee codes, job codes, cost centers
- Support common PII categories across client spreadsheets
"""

from __future__ import annotations

import hashlib
import re
from typing import Any

# Direct column hints for fields that should be masked.
COLUMN_HINTS: dict[str, str] = {
    # Names
    "name": "FULL_NAME",
    "full_name": "FULL_NAME",
    "fullname": "FULL_NAME",
    "employee_name": "FULL_NAME",
    "user_name": "USERNAME",
    "username": "USERNAME",
    "contact_name": "FULL_NAME",
    "manager_name": "FULL_NAME",
    "head_name": "FULL_NAME",

    # Contact
    "email": "EMAIL",
    "email_address": "EMAIL",
    "work_email": "EMAIL",
    "personal_email": "EMAIL",
    "phone": "PHONE",
    "phone_number": "PHONE",
    "mobile": "PHONE",
    "telephone": "PHONE",

    # Government / identity
    "ssn": "SSN",
    "social_security": "SSN",
    "social_security_number": "SSN",
    "sin": "SIN",
    "national_id": "NATIONAL_ID",
    "passport": "PASSPORT",
    "passport_number": "PASSPORT",
    "driver_license": "DRIVERS_LICENSE",
    "drivers_license": "DRIVERS_LICENSE",
    "license_number": "DRIVERS_LICENSE",
    "pan": "PAN",
    "aadhaar": "AADHAAR",
    "aadhaar_number": "AADHAAR",
    "tax_id": "TAX_ID",
    "tin": "TAX_ID",
    "ein": "TAX_ID",

    # Financial
    "bank_account": "BANK_ACCOUNT",
    "account_number": "BANK_ACCOUNT",
    "iban": "IBAN",
    "swift": "SWIFT",
    "routing_number": "ROUTING_NUMBER",
    "credit_card": "CREDIT_CARD",
    "card_number": "CREDIT_CARD",
    "cvv": "CVV",

    # Credentials / secrets
    "password": "PASSWORD",
    "pwd": "PASSWORD",
    "secret": "PASSWORD",
    "token": "TOKEN",
    "api_key": "TOKEN",

    # Location
    "address": "ADDRESS",
    "street_address": "ADDRESS",
    "city": "CITY",
    "state": "STATE",
    "country": "COUNTRY",
    "zip": "ZIP_CODE",
    "zip_code": "ZIP_CODE",
    "postal_code": "ZIP_CODE",
    "pincode": "ZIP_CODE",

    # Sensitive demographic / HR attributes
    "dob": "DATE_OF_BIRTH",
    "date_of_birth": "DATE_OF_BIRTH",
    "birth_date": "DATE_OF_BIRTH",
    "birthdate": "DATE_OF_BIRTH",
    "gender": "GENDER",
    "sex": "GENDER",
    "marital_status": "MARITAL_STATUS",
    "religion": "RELIGION",
    "ethnicity": "ETHNICITY",
    "race": "RACE",
    "nationality": "NATIONALITY",
    "medical_record": "MEDICAL_RECORD",
    "medical": "MEDICAL_INFO",
    "diagnosis": "MEDICAL_INFO",
    "medication": "MEDICAL_INFO",
    "disability": "MEDICAL_INFO",

    # User identifiers
    "employee_id": "EMPLOYEE_ID",
    "emp_id": "EMPLOYEE_ID",
    "user_id": "USER_ID",
    "customer_id": "CUSTOMER_ID",

    # Online identifiers
    "ip_address": "IP_ADDRESS",
    "mac_address": "MAC_ADDRESS",
    "url": "URL",
    "website": "URL",
    "linkedin": "URL",
    "twitter": "URL",
}

# Business / operational reference columns that should generally be preserved.
# These are common in HR audit extracts and are not masked unless they match a strong PII value pattern.
PRESERVE_COLUMNS = {
    "employee_code",
    "employee code",
    "company_code",
    "company code",
    "company_code_description",
    "company code description",
    "personnel_area",
    "personnel area",
    "personnel_sub_area",
    "personnel sub area",
    "employee_group",
    "employee group",
    "employee_sub_group",
    "employee sub group",
    "payroll_area_code",
    "payroll area code",
    "payroll_area_description",
    "payroll area description",
    "job_code",
    "job code",
    "job_text",
    "job text",
    "position_code",
    "position code",
    "position_text",
    "position text",
    "org_unit_code",
    "org.unit code",
    "org unit code",
    "organizational_unit",
    "organizational unit",
    "reporting_manager_id",
    "reporting manager id",
    "dept_head_id",
    "dept. head id",
    "department head id",
    "cost_center",
    "cost center",
}

VALUE_PATTERNS: list[tuple[str, str]] = [
    ("EMAIL", r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"),
    ("PHONE", r"\b(?:\+\d{1,3}[\s\-.]?)?\(?\d{3}\)?[\s\-.]?\d{3}[\s\-.]?\d{4}\b"),
    ("SSN", r"\b\d{3}[-\s]\d{2}[-\s]\d{4}\b"),
    ("SIN", r"\b\d{3}[-\s]\d{3}[-\s]\d{3}\b"),
    ("PAN", r"\b[A-Z]{5}\d{4}[A-Z]\b"),
    ("AADHAAR", r"\b\d{4}[-\s]\d{4}[-\s]\d{4}\b"),
    ("CREDIT_CARD", r"\b(?:\d[ -]*?){13,19}\b"),
    ("IBAN", r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b"),
    ("SWIFT", r"\b[A-Z]{4}[A-Z]{2}[A-Z0-9]{2}([A-Z0-9]{3})?\b"),
    ("IP_ADDRESS", r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    ("MAC_ADDRESS", r"\b(?:[0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}\b"),
    ("PASSPORT", r"\b[A-Z]{1,2}\d{6,9}\b"),
    ("DRIVERS_LICENSE", r"\b[A-Z]{1,2}\d{5,8}\b"),
    ("TOKEN", r"(?i)\b(?:token|api[_\-]?key)\s*[:=]\s*[A-Za-z0-9+/=\-_]{20,}\b"),
    ("PASSWORD", r"(?i)\bpassword\s*[:=]\s*\S+"),
    ("URL", r"https?://[^\s]+"),
    ("ZIP_CODE", r"\b\d{5}(?:[-\s]\d{4})?\b"),
    ("DATE_OF_BIRTH", r"\b(?:0?[1-9]|1[0-2])[/\-\.](?:0?[1-9]|[12]\d|3[01])[/\-\.](?:19|20)\d{2}\b"),
    ("DATE_OF_BIRTH", r"\b(?:19|20)\d{2}[/\-\.](?:0?[1-9]|1[0-2])[/\-\.](?:0?[1-9]|[12]\d|3[01])\b"),
    ("SALARY", r"(?i)\$\s*[\d,]+(?:\.\d{2})?"),
    ("GSTIN", r"\b\d{2}[A-Z]{5}\d{4}[A-Z][A-Z\d]Z[A-Z\d]\b"),
]

MASK_STRATEGIES: dict[str, callable] = {
    "EMAIL": lambda v: f"user_{_hash_token(v)}@masked.local",
    "PHONE": lambda v: _mask_digits(str(v), keep_last=4),
    "SSN": lambda v: "***-**-" + _digits_only(v)[-4:],
    "SIN": lambda v: "***-***-" + _digits_only(v)[-3:],
    "PAN": lambda v: str(v)[0] + "*" * 8 + str(v)[-1],
    "AADHAAR": lambda v: "XXXX-XXXX-" + _digits_only(v)[-4:],
    "CREDIT_CARD": lambda v: "**** **** **** " + _digits_only(v)[-4:],
    "IBAN": lambda v: str(v)[:4] + "*" * max(len(str(v)) - 8, 4) + str(v)[-4:],
    "SWIFT": lambda v: str(v)[:4] + "****" + str(v)[-3:],
    "IP_ADDRESS": lambda v: ".".join(p if i < 2 else "***" for i, p in enumerate(str(v).split("."))),
    "MAC_ADDRESS": lambda v: ":".join(p if i < 3 else "**" for i, p in enumerate(str(v).split(":"))),
    "PASSPORT": lambda v: str(v)[0] + "*" * (max(len(str(v)) - 2, 2)) + str(v)[-1],
    "DRIVERS_LICENSE": lambda v: str(v)[0] + "*" * (max(len(str(v)) - 2, 2)) + str(v)[-1],
    "TOKEN": lambda v: "[MASKED-TOKEN]",
    "PASSWORD": lambda v: "********",
    "URL": lambda v: "[MASKED-URL]",
    "ZIP_CODE": lambda v: str(v)[:2] + "***",
    "DATE_OF_BIRTH": lambda v: "**/**/****",
    "SALARY": lambda v: "[MASKED-SALARY]",
    "GSTIN": lambda v: str(v)[:2] + "*" * 11 + str(v)[13:],
    "BANK_ACCOUNT": lambda v: "*" * max(len(_digits_only(v)) - 4, 4) + _digits_only(v)[-4:],
    "NATIONAL_ID": lambda v: "*" * max(len(str(v)) - 4, 4) + str(v)[-4:],
    "EMPLOYEE_ID": lambda v: f"EMP-{_hash_token(v, 6)}",
    "USER_ID": lambda v: f"UID-{_hash_token(v, 6)}",
    "CUSTOMER_ID": lambda v: f"CUST-{_hash_token(v, 6)}",
    "FULL_NAME": lambda v: f"User-{_hash_token(v, 8)}",
    "USERNAME": lambda v: f"user_{_hash_token(v, 8)}",
    "ADDRESS": lambda v: "[MASKED-ADDRESS]",
    "CITY": lambda v: "[MASKED-CITY]",
    "STATE": lambda v: "[MASKED-STATE]",
    "COUNTRY": lambda v: "[MASKED-COUNTRY]",
    "GENDER": lambda v: "[MASKED]",
    "MARITAL_STATUS": lambda v: "[MASKED]",
    "RELIGION": lambda v: "[MASKED]",
    "ETHNICITY": lambda v: "[MASKED]",
    "RACE": lambda v: "[MASKED]",
    "NATIONALITY": lambda v: "[MASKED]",
    "MEDICAL_RECORD": lambda v: f"MR-{_hash_token(v, 6)}",
    "MEDICAL_INFO": lambda v: "[MASKED-MEDICAL]",
    "TAX_ID": lambda v: "*" * max(len(_digits_only(v)) - 4, 4) + _digits_only(v)[-4:],
    "SSN": lambda v: "***-**-" + _digits_only(v)[-4:],
}

def _normalize_col(col: str) -> str:
    return re.sub(r"[\s_\-]+", "_", str(col).strip().lower())


def _digits_only(value: Any) -> str:
    return re.sub(r"\D", "", str(value))


def _mask_digits(value: str, keep_last: int = 4) -> str:
    digits = _digits_only(value)
    if len(digits) <= keep_last:
        return "*" * len(digits)
    return "*" * (len(digits) - keep_last) + digits[-keep_last:]


def _hash_token(value: Any, length: int = 8) -> str:
    return hashlib.sha256(str(value).encode("utf-8")).hexdigest()[:length].upper()


def detect_pii_type_by_column(col: str) -> str | None:
    key = _normalize_col(col)
    if key in PRESERVE_COLUMNS:
        return None

    if key in COLUMN_HINTS:
        return COLUMN_HINTS[key]

    for hint_key, pii_type in COLUMN_HINTS.items():
        if hint_key in key or key in hint_key:
            return pii_type

    return None


def detect_pii_type_by_value(value: Any) -> str | None:
    s = str(value).strip()
    if not s or s.lower() in {"nan", "none", "nat"}:
        return None

    for pii_type, pattern in VALUE_PATTERNS:
        if re.fullmatch(pattern, s) or re.search(pattern, s):
            return pii_type

    return None


def mask_value(value: Any, pii_type: str) -> Any:
    if value is None:
        return value
    if str(value).strip().lower() in {"", "nan", "none", "nat"}:
        return value

    strategy = MASK_STRATEGIES.get(pii_type)
    if strategy:
        try:
            return strategy(value)
        except Exception:
            return "[MASKED]"
    return "[MASKED]"


def should_mask(col: str, value: Any) -> tuple[bool, str]:
    """
    Returns (should_mask, pii_type).
    Priority:
    1) explicit sensitive column name
    2) strong value-based pattern match
    """
    pii_type = detect_pii_type_by_column(col)
    if pii_type:
        return True, pii_type

    pii_type = detect_pii_type_by_value(value)
    if pii_type:
        return True, pii_type

    return False, ""
