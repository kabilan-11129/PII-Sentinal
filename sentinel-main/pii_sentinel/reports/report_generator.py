"""
report_generator.py — Generate downloadable CSV compliance reports.

Each report row contains:
  • File / source name
  • Data source type  (Email, Database, Archive, Spreadsheet, Document, etc.)
  • Storage location
  • Detected PII type
  • Detected PII value (masked for safety)
  • Sensitivity level
  • Risk level
  • Data owner (inferred or assigned)
  • DPDPA section reference
  • Recommended action
  • Timestamp

Aligned with India's Digital Personal Data Protection Act (DPDPA) 2023.
"""

import csv
import io
import os
from datetime import datetime
from typing import Dict, List

from scanner.classifier import classify_pii_type, assess_risk


# ──────────────────────────────────────────────
# DPDPA section references per PII type
# ──────────────────────────────────────────────
DPDPA_REFERENCE: Dict[str, str] = {
    "Email"      : "Section 4,5 — Consent required for processing contact data",
    "Phone"      : "Section 4,5 — Consent required for processing contact data",
    "DOB"        : "Section 9 — Additional protections for age-related data",
    "PAN"        : "Section 8 — Enhanced security safeguards for financial ID",
    "Aadhaar"    : "Section 8 — Enhanced security safeguards for government ID",
    "Card"       : "Section 8 — Enhanced security safeguards; PCI-DSS compliance",
    "Name"       : "Section 4,5 — Lawful basis required for processing personal data",
    "Passport"   : "Section 8 — Government-issued ID; strict access controls required",
    "IFSC"       : "Section 8 — Financial routing data; encrypt and restrict access",
    "BankAccount": "Section 8 — Financial account data; PCI-DSS & RBI guidelines",
    "Vehicle"    : "Section 4 — Personal identifier requiring lawful processing basis",
    "HealthData" : "Section 8 — Sensitive personal data; explicit consent required",
    "IPAddress"  : "Section 4 — Network identifier; assess re-identification risk",
}

RECOMMENDED_ACTIONS: Dict[str, str] = {
    "Email"      : "Obtain explicit consent; apply pseudonymization; restrict access",
    "Phone"      : "Obtain consent; limit access rights; log all access",
    "DOB"        : "Verify age-processing rules; restrict access; apply data minimisation",
    "PAN"        : "Encrypt at rest & in transit; strict access controls; audit usage",
    "Aadhaar"    : "Encrypt at rest; minimise retention; restrict to authorised personnel",
    "Card"       : "PCI-DSS compliance required; tokenize or mask; purge after use",
    "Name"       : "Ensure lawful basis; apply data minimisation; review retention",
    "Passport"   : "Encrypt; restrict to authorised use; log every access event",
    "IFSC"       : "Encrypt; restrict to payment workflows; monitor for exfiltration",
    "BankAccount": "PCI-DSS & RBI data localisation; tokenize; restricted access",
    "Vehicle"    : "Assess necessity; apply access controls; review retention period",
    "HealthData" : "Explicit consent required; encrypt; restrict to medical personnel",
    "IPAddress"  : "Assess re-identification risk; apply anonymisation where possible",
}


# ──────────────────────────────────────────────
# Data source inference
# ──────────────────────────────────────────────

def infer_data_source(filename: str) -> str:
    """
    Infer the data source type from file extension.
    In a full enterprise deployment this would be driven by connector metadata.
    """
    ext = os.path.splitext(filename)[1].lower()
    mapping = {
        # Email
        ".eml"    : "Email",
        ".msg"    : "Email",
        # Database
        ".db"     : "Database",
        ".sqlite" : "Database",
        ".sqlite3": "Database",
        ".sql"    : "Database",
        # Archives
        ".zip"    : "Archive",
        ".tar"    : "Archive",
        ".gz"     : "Archive",
        ".tgz"    : "Archive",
        ".7z"     : "Archive",
        ".rar"    : "Archive",
        # Spreadsheets
        ".csv"    : "Spreadsheet",
        ".xlsx"   : "Spreadsheet",
        ".xls"    : "Spreadsheet",
        # Documents
        ".pdf"    : "Document (PDF)",
        ".docx"   : "Document (DOCX)",
        ".pptx"   : "Presentation (PPTX)",
        ".rtf"    : "Document (RTF)",
        ".odt"    : "Document (ODT)",
        ".ods"    : "Spreadsheet (ODS)",
        ".msg"    : "Email (Outlook MSG)",
        # Plain text variants
        ".txt"    : "Plain Text",
        ".log"    : "Log File",
        ".md"     : "Markdown",
        # Structured data
        ".json"   : "Data File (JSON)",
        ".xml"    : "Data File (XML)",
        # Web
        ".html"   : "Web Document",
        ".htm"    : "Web Document",
    }
    return mapping.get(ext, "File System")


def infer_storage_location(filename: str) -> str:
    """
    Infer or label the storage location.
    In production: would map to actual cloud buckets, file-server paths, etc.
    """
    return "On-Premises / Local Upload"


# ──────────────────────────────────────────────
# Value masking (prevent full PII exposure in reports)
# ──────────────────────────────────────────────

def mask_value(value: str, pii_type: str) -> str:
    """
    Partially mask a PII value for safe display and reporting.

    Email        → us***@example.com
    Phone        → ●●●●●●7890
    PAN          → ABCD***34F
    Aadhaar      → ●●●●●●●●1234
    Card         → ●●●●●●●●●●●●3456
    DOB          → ●●/●●/1990
    Passport     → X●●●●●●●  (first char + masked)
    BankAccount  → ●●●●●●1234
    IFSC         → ABCD0●●●●●●
    Name         → First ●●●●●  (first name visible)
    HealthData   → keyword as-is (not truly masked; safe to expose category)
    IPAddress    → xxx.xxx.●.●
    Vehicle      → XX00●●●●
    """
    value = value.strip()

    if pii_type == "Email":
        parts = value.split("@")
        if len(parts) == 2:
            local = parts[0]
            return (local[:2] + "***" if len(local) > 2 else "***") + "@" + parts[1]

    elif pii_type == "Phone":
        digits = "".join(c for c in value if c.isdigit())
        return ("●" * (len(digits) - 4) + digits[-4:]) if len(digits) >= 4 else "●" * len(value)

    elif pii_type == "PAN" and len(value) == 10:
        return value[:4] + "***" + value[-3:]

    elif pii_type == "Aadhaar":
        digits = "".join(c for c in value if c.isdigit())
        return ("●" * (len(digits) - 4) + digits[-4:]) if len(digits) >= 4 else "●" * len(digits)

    elif pii_type == "Card":
        digits = "".join(c for c in value if c.isdigit())
        return ("●" * (len(digits) - 4) + digits[-4:]) if len(digits) >= 4 else "●" * len(digits)

    elif pii_type == "DOB" and len(value) >= 4:
        return "●●/●●/" + value[-4:]

    elif pii_type == "Passport" and len(value) >= 2:
        return value[0] + "●" * (len(value) - 1)

    elif pii_type == "BankAccount":
        digits = "".join(c for c in value if c.isdigit())
        return ("●" * (len(digits) - 4) + digits[-4:]) if len(digits) >= 4 else "●" * len(digits)

    elif pii_type == "IFSC" and len(value) >= 5:
        return value[:5] + "●" * (len(value) - 5)

    elif pii_type == "Name":
        words = value.split()
        if len(words) >= 2:
            return words[0] + " " + " ".join("●" * len(w) for w in words[1:])
        return value  # single-word name shown as-is

    elif pii_type in ("HealthData", "IPAddress", "Vehicle"):
        return value  # category labels / low-risk identifiers shown as-is

    # Generic fallback
    return (value[:2] + "●" * (len(value) - 4) + value[-2:]) if len(value) > 4 else "●" * len(value)


# ──────────────────────────────────────────────
# Build report rows
# ──────────────────────────────────────────────

def build_rows(filename: str,
               pii_results: Dict[str, List[str]],
               scan_time: str = None,
               data_owner: str = "Unassigned") -> List[Dict]:
    """
    Convert PII results for one file/source into a list of flat dicts
    (one dict per detected PII item).
    """
    if scan_time is None:
        scan_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    risk_level, risk_reason = assess_risk(pii_results)
    source_type = infer_data_source(filename)
    storage_loc = infer_storage_location(filename)
    rows: List[Dict] = []

    for pii_type, values in pii_results.items():
        if not values:
            continue
        sensitivity = classify_pii_type(pii_type)
        dpdpa_ref   = DPDPA_REFERENCE.get(pii_type, "Section 4 — General personal data processing")
        action      = RECOMMENDED_ACTIONS.get(pii_type, "Review, assess, and apply data minimisation")
        for val in values:
            rows.append({
                "file_name"         : filename,
                "data_source"       : source_type,
                "storage_location"  : storage_loc,
                "pii_type"          : pii_type,
                "pii_value_masked"  : mask_value(val, pii_type),
                "sensitivity"       : sensitivity,
                "risk_level"        : risk_level,
                "risk_reason"       : risk_reason,
                "data_owner"        : data_owner,
                "dpdpa_reference"   : dpdpa_ref,
                "recommended_action": action,
                "timestamp"         : scan_time,
            })

    # If no PII at all, add a single clean-bill-of-health row
    if not rows:
        rows.append({
            "file_name"         : filename,
            "data_source"       : source_type,
            "storage_location"  : storage_loc,
            "pii_type"          : "None",
            "pii_value_masked"  : "—",
            "sensitivity"       : "LOW",
            "risk_level"        : "LOW",
            "risk_reason"       : "No PII detected",
            "data_owner"        : data_owner,
            "dpdpa_reference"   : "N/A",
            "recommended_action": "No action required",
            "timestamp"         : scan_time,
        })

    return rows


# ──────────────────────────────────────────────
# CSV export
# ──────────────────────────────────────────────

COLUMNS = [
    "file_name",
    "data_source",
    "storage_location",
    "pii_type",
    "pii_value_masked",
    "sensitivity",
    "risk_level",
    "risk_reason",
    "data_owner",
    "dpdpa_reference",
    "recommended_action",
    "timestamp",
]


def rows_to_csv(rows: List[Dict]) -> str:
    """Serialize a list of row dicts into a CSV string."""
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=COLUMNS, extrasaction="ignore")
    writer.writeheader()
    writer.writerows(rows)
    return output.getvalue()


# ──────────────────────────────────────────────
# Summary statistics
# ──────────────────────────────────────────────

DPDPA_COLUMNS = [
    "file_name",
    "data_source",
    "storage_location",
    "data_owner",
    "pii_type",
    "pii_count",
    "security_level",
    "data_subject_type",
    "purpose_of_processing",
    "consent_status",
    "lawful_basis",
    "dpdpa_section",
    "retention_policy",
    "compliance_score",
    "recommended_action",
    "timestamp",
]


def build_dpdpa_report_csv(inventory_records: List[Dict]) -> str:
    """
    Generate a DPDPA compliance report as CSV.

    Each row represents one file from the personal data inventory,
    with all DPDPA-required metadata fields.
    """
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=DPDPA_COLUMNS, extrasaction="ignore")
    writer.writeheader()

    for record in inventory_records:
        pii_types = record.get("detected_personal_data_types", [])
        pii_counts = record.get("pii_counts", {})
        consent_reqs = record.get("consent_requirements", [])
        sections = ", ".join(set(c.get("section", "") for c in consent_reqs)) if consent_reqs else "N/A"

        for pii_type in pii_types:
            action = RECOMMENDED_ACTIONS.get(pii_type, "Review and apply data minimisation")
            writer.writerow({
                "file_name": record.get("file_name", ""),
                "data_source": record.get("data_source", ""),
                "storage_location": record.get("storage_location", ""),
                "data_owner": record.get("data_owner_department", ""),
                "pii_type": pii_type,
                "pii_count": pii_counts.get(pii_type, 0),
                "security_level": record.get("security_level", ""),
                "data_subject_type": ", ".join(record.get("data_subject_type", [])),
                "purpose_of_processing": "; ".join(record.get("purpose_of_processing", [])),
                "consent_status": record.get("consent_status", ""),
                "lawful_basis": record.get("lawful_basis", ""),
                "dpdpa_section": sections,
                "retention_policy": record.get("retention_policy", ""),
                "compliance_score": record.get("compliance_score", 0),
                "recommended_action": action,
                "timestamp": record.get("created_at", ""),
            })

        # If no PII types, still add a row for the file
        if not pii_types:
            writer.writerow({
                "file_name": record.get("file_name", ""),
                "data_source": record.get("data_source", ""),
                "storage_location": record.get("storage_location", ""),
                "data_owner": record.get("data_owner_department", ""),
                "pii_type": "None",
                "pii_count": 0,
                "security_level": record.get("security_level", "PUBLIC"),
                "data_subject_type": "N/A",
                "purpose_of_processing": "N/A",
                "consent_status": "not_applicable",
                "lawful_basis": "No personal data",
                "dpdpa_section": "N/A",
                "retention_policy": "Standard retention",
                "compliance_score": 100,
                "recommended_action": "No action required",
                "timestamp": record.get("created_at", ""),
            })

    return output.getvalue()


def build_summary(rows: List[Dict]) -> Dict:
    """
    Compute dashboard summary stats from the flat row list.
    """
    if not rows:
        return {
            "total_files"        : 0,
            "total_pii"          : 0,
            "high_risk_files"    : 0,
            "critical_risk_files": 0,
            "pii_type_counts"    : {},
            "risk_counts"        : {},
            "source_counts"      : {},
            "sensitivity_counts" : {},
        }

    file_names: set = set()
    pii_type_counts: Dict[str, int] = {}
    risk_per_file: Dict[str, str] = {}
    source_per_file: Dict[str, str] = {}
    sensitivity_counts: Dict[str, int] = {}
    total_pii = 0

    for r in rows:
        file_names.add(r["file_name"])
        risk_per_file[r["file_name"]] = r["risk_level"]
        source_per_file[r["file_name"]] = r.get("data_source", "Unknown")

        if r["pii_type"] != "None":
            total_pii += 1
            pii_type_counts[r["pii_type"]] = pii_type_counts.get(r["pii_type"], 0) + 1
            sens = r.get("sensitivity", "LOW")
            sensitivity_counts[sens] = sensitivity_counts.get(sens, 0) + 1

    risk_counts: Dict[str, int] = {}
    for rl in risk_per_file.values():
        risk_counts[rl] = risk_counts.get(rl, 0) + 1

    source_counts: Dict[str, int] = {}
    for src in source_per_file.values():
        source_counts[src] = source_counts.get(src, 0) + 1

    return {
        "total_files"        : len(file_names),
        "total_pii"          : total_pii,
        "high_risk_files"    : risk_counts.get("HIGH", 0) + risk_counts.get("CRITICAL", 0),
        "critical_risk_files": risk_counts.get("CRITICAL", 0),
        "pii_type_counts"    : pii_type_counts,
        "risk_counts"        : risk_counts,
        "source_counts"      : source_counts,
        "sensitivity_counts" : sensitivity_counts,
    }
