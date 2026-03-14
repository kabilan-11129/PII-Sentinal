"""
pii_detector.py — Detect sensitive personal data using regex patterns.

Detects:
  • Email addresses
  • Indian phone numbers        (10 digits starting with 6-9, optional +91/0 prefix)
  • PAN numbers                 (ABCDE1234F format)
  • Aadhaar numbers             (12 digits, optionally space/dash separated)
  • Credit/Debit card numbers   (Visa, MasterCard, RuPay, etc.)
  • Date of Birth               (DD/MM/YYYY or DD-MM-YYYY)
  • Full Name                   (Title + capitalized name patterns)
  • Passport Number             (Indian: one letter + 7 digits)
  • IFSC Code                   (4 letters + 0 + 6 alphanumeric chars)
  • Bank Account Number         (9-18 digits in account-number keyword context)
  • Vehicle Registration        (Indian format: XX00XX0000)
  • Health Data                 (blood types, clinical condition keywords)
  • IPv4 Address                (standard dotted-quad notation)

Returns detected values grouped by type with counts.
"""

import re
from typing import Dict, List

# DB auto-store: imported lazily to avoid circular imports
_db_store = None

def _get_db_store():
    """Lazy-load the db_store module to prevent import-time DB errors."""
    global _db_store
    if _db_store is None:
        try:
            from scanner.db_store import insert_detected_pii as _insert
            _db_store = _insert
        except Exception:
            _db_store = False          # Mark as unavailable, don't retry
    return _db_store if _db_store else None


# ──────────────────────────────────────────────
# Compiled regex patterns
# ──────────────────────────────────────────────

# Standard email
EMAIL_RE = re.compile(
    r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"
)

# Indian mobile: optional +91 or 0 prefix, then 10 digits starting 6-9
PHONE_RE = re.compile(
    r"(?<!\d)(?:\+91[\s\-]?|0)?[6-9]\d{9}(?!\d)"
)

# PAN: 5 uppercase letters + 4 digits + 1 uppercase letter
PAN_RE = re.compile(
    r"\b[A-Z]{5}[0-9]{4}[A-Z]\b"
)

# Aadhaar: 12 digits with optional spaces/dashes in 4-4-4 groups
AADHAAR_RE = re.compile(
    r"\b\d{4}[\s\-]?\d{4}[\s\-]?\d{4}\b"
)

# Credit/Debit Card: Visa (4xxx), MasterCard (5xxx), RuPay (6xxx)
CARD_RE = re.compile(
    r"\b(?:4\d{3}|5[1-5]\d{2}|6(?:011|5\d{2}))[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4}\b"
)

# Date of Birth: DD/MM/YYYY or DD-MM-YYYY
DOB_RE = re.compile(
    r"\b(?:0[1-9]|[12]\d|3[01])[\/\-](?:0[1-9]|1[0-2])[\/\-](?:19|20)\d{2}\b"
)

# Full Name: salutation followed by 1–3 capitalized words
NAME_RE = re.compile(
    r"\b(?:Mr|Mrs|Ms|Miss|Dr|Prof|Er|Shri|Smt|Kum|Sri)\.?\s+"
    r"[A-Z][a-z]{1,24}(?:\s+[A-Z][a-z]{1,24}){0,2}\b"
)

# Indian Passport: one uppercase letter + exactly 7 digits
PASSPORT_RE = re.compile(
    r"\b[A-Z]\d{7}\b"
)

# IFSC Code: 4 uppercase letters + mandatory 0 + 6 alphanumeric chars
IFSC_RE = re.compile(
    r"\b[A-Z]{4}0[A-Z0-9]{6}\b"
)

# Bank Account Number: 9–18 digits following an account-number keyword
# Capturing group returns only the digit string
BANK_ACCOUNT_RE = re.compile(
    r"(?i)(?:account\s*(?:no|number|num|#)[\s:=.]*|a\/c[\s:=.]*(?:no\.?[\s:=.]*)?)(\d{9,18})"
)

# Indian Vehicle Registration: XX00XX0000 or XX00X0000
VEHICLE_RE = re.compile(
    r"\b[A-Z]{2}\s?\d{2}\s?[A-Z]{1,3}\s?\d{4}\b"
)

# IPv4 address (excludes loopback 127.x.x.x and common binary false positives)
IPV4_RE = re.compile(
    r"\b(?!127\.)(?:\d{1,3}\.){3}\d{1,3}\b"
)

# Blood type (A+, AB-, O+ etc.) — optionally preceded by "blood group/type"
BLOOD_TYPE_RE = re.compile(
    r"\b(?:blood[\s\-]?(?:group|type)[\s:=]*)?(?:A\+|A\-|B\+|B\-|AB\+|AB\-|O\+|O\-)\b"
)

# Clinical / health condition keywords
HEALTH_KEYWORD_RE = re.compile(
    r"\b(?:diabetes(?:\s+mellitus)?|hypertension|HIV|AIDS|cancer|tuberculosis|TB|"
    r"cardiac\s+(?:arrest|disease)|thyroid|asthma|arthritis|diagnosis|prescription|"
    r"medication|treatment|surgery|allergy|allergic|cholesterol|hemoglobin|insulin|"
    r"chemotherapy|disability|mental\s+health|psychiatric|physiotherapy|hepatitis|"
    r"dengue|malaria|typhoid|fracture|transplant|dialysis|biopsy|immunodeficiency)\b",
    re.IGNORECASE,
)


# ──────────────────────────────────────────────
# Individual detector functions
# ──────────────────────────────────────────────

def detect_emails(text: str) -> List[str]:
    return EMAIL_RE.findall(text)


def detect_phones(text: str) -> List[str]:
    return PHONE_RE.findall(text)


def detect_pan(text: str) -> List[str]:
    return PAN_RE.findall(text)


def detect_aadhaar(text: str) -> List[str]:
    return AADHAAR_RE.findall(text)


def detect_cards(text: str) -> List[str]:
    return CARD_RE.findall(text)


def detect_dob(text: str) -> List[str]:
    return DOB_RE.findall(text)


def detect_names(text: str) -> List[str]:
    return NAME_RE.findall(text)


def detect_passport(text: str) -> List[str]:
    return PASSPORT_RE.findall(text)


def detect_ifsc(text: str) -> List[str]:
    return IFSC_RE.findall(text)


def detect_bank_account(text: str) -> List[str]:
    """Return bank account digit strings found in account-number context."""
    return BANK_ACCOUNT_RE.findall(text)


def detect_vehicle(text: str) -> List[str]:
    return [m.replace(" ", "") for m in VEHICLE_RE.findall(text)]


def detect_ip_addresses(text: str) -> List[str]:
    """Return valid IPv4 addresses, filtering out malformed octets."""
    results = []
    for m in IPV4_RE.findall(text):
        if all(0 <= int(o) <= 255 for o in m.split(".")):
            results.append(m)
    return results


def detect_health_data(text: str) -> List[str]:
    """Return blood-type tokens and clinical condition keywords found in text."""
    blood    = [b.strip() for b in BLOOD_TYPE_RE.findall(text)]
    keywords = list({k.strip() for k in HEALTH_KEYWORD_RE.findall(text)})
    return blood + keywords


# ──────────────────────────────────────────────
# Aggregate detector
# ──────────────────────────────────────────────

def detect_all_pii(text: str, *, source_id: str = "AUTO", store_to_db: bool = True) -> Dict[str, List[str]]:
    """
    Run every detector on the given text.

    Args:
        text:        The input text to scan.
        source_id:   Identifier for the scan source (file name, user, etc.)
                     used when storing results in MySQL.
        store_to_db: If True, automatically insert detected PII into the
                     personal_data_records MySQL table.

    Returns a dict keyed by PII category:
        Email, Phone, PAN, Aadhaar, Card, DOB,
        Name, Passport, IFSC, BankAccount, Vehicle, HealthData, IPAddress
    """
    results = {
        "Email"      : detect_emails(text),
        "Phone"      : detect_phones(text),
        "PAN"        : detect_pan(text),
        "Aadhaar"    : detect_aadhaar(text),
        "Card"       : detect_cards(text),
        "DOB"        : detect_dob(text),
        "Name"       : detect_names(text),
        "Passport"   : detect_passport(text),
        "IFSC"       : detect_ifsc(text),
        "BankAccount": detect_bank_account(text),
        "Vehicle"    : detect_vehicle(text),
        "HealthData" : detect_health_data(text),
        "IPAddress"  : detect_ip_addresses(text),
    }

    # Auto-store detected PII to MySQL (non-blocking, never fails the scan)
    if store_to_db:
        try:
            _insert = _get_db_store()
            if _insert:
                count = _insert(results, source_id=source_id)
                if count > 0:
                    print(f"[DB] Stored {count} PII records for source '{source_id}'")
        except Exception as e:
            print(f"[DB] Auto-store warning (non-fatal): {e}")

    return results


def count_pii(pii_results: Dict[str, List[str]]) -> Dict[str, int]:
    """Return { pii_type: count } for each type."""
    return {k: len(v) for k, v in pii_results.items()}


def total_pii(pii_results: Dict[str, List[str]]) -> int:
    """Return total number of PII items across all types."""
    return sum(len(v) for v in pii_results.values())
