"""
data_inventory.py — DPDPA-Aligned Personal Data Inventory for PII Sentinel

Maintains a central personal data catalog as required by India's
Digital Personal Data Protection Act (DPDPA) 2023.

For every scanned file, stores:
    - file_name, detected personal data types, data owner/department
    - storage location, security level
    - purpose of processing, consent status, data subject type
    - retention period, lawful basis, data fiduciary info

Provides:
    - Personal data catalog CRUD
    - Purpose & consent metadata management
    - DPDPA compliance scoring per file
    - Aggregate compliance summary for dashboard
"""

import copy
from datetime import datetime
from typing import Dict, List, Optional


# ── In-memory inventory store ────────────────────────────────────────────────
# Key: file_name (str) → inventory record (dict)
_inventory_store: Dict[str, dict] = {}


def _now() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


# ── PII type → DPDPA data subject type mapping ──────────────────────────────
PII_SUBJECT_MAP = {
    "Email":       "employee",
    "Phone":       "employee",
    "Name":        "employee",
    "DOB":         "employee",
    "PAN":         "employee",
    "Aadhaar":     "citizen",
    "Passport":    "citizen",
    "Card":        "customer",
    "BankAccount": "customer",
    "IFSC":        "customer",
    "HealthData":  "patient",
    "IPAddress":   "user",
    "Vehicle":     "citizen",
}

# ── PII type → default processing purpose ────────────────────────────────────
PII_PURPOSE_MAP = {
    "Email":       "Communication and identity verification",
    "Phone":       "Communication and identity verification",
    "Name":        "Identity management and HR operations",
    "DOB":         "Age verification and HR payroll processing",
    "PAN":         "Tax compliance and financial verification (Income Tax Act)",
    "Aadhaar":     "Identity verification under Aadhaar Act provisions",
    "Passport":    "International travel and identity verification",
    "Card":        "Payment processing and financial transactions",
    "BankAccount": "Salary disbursement and financial operations",
    "IFSC":        "Banking and payment routing",
    "HealthData":  "Medical records management and insurance processing",
    "IPAddress":   "Network logging and security monitoring",
    "Vehicle":     "Asset management and compliance records",
}

# ── DPDPA Section references for consent requirements ────────────────────────
DPDPA_CONSENT_REQ = {
    "Email":       {"section": "Section 6", "consent_type": "notice_based", "description": "Notice and consent for contact data"},
    "Phone":       {"section": "Section 6", "consent_type": "notice_based", "description": "Notice and consent for contact data"},
    "Name":        {"section": "Section 4", "consent_type": "legitimate_use", "description": "Lawful purpose for identity data"},
    "DOB":         {"section": "Section 9", "consent_type": "explicit", "description": "Additional protections for minors' data"},
    "PAN":         {"section": "Section 8(3)", "consent_type": "statutory", "description": "Statutory obligation under Income Tax Act"},
    "Aadhaar":     {"section": "Section 8(3)", "consent_type": "statutory", "description": "Statutory obligation under Aadhaar Act"},
    "Passport":    {"section": "Section 8", "consent_type": "explicit", "description": "Explicit consent for government ID"},
    "Card":        {"section": "Section 8", "consent_type": "explicit", "description": "Explicit consent for financial data; PCI-DSS"},
    "BankAccount": {"section": "Section 8", "consent_type": "explicit", "description": "Explicit consent for financial data; RBI guidelines"},
    "IFSC":        {"section": "Section 8", "consent_type": "notice_based", "description": "Financial routing data consent"},
    "HealthData":  {"section": "Section 8(1)", "consent_type": "explicit", "description": "Explicit consent for sensitive health data"},
    "IPAddress":   {"section": "Section 4", "consent_type": "legitimate_use", "description": "Network logging under legitimate interest"},
    "Vehicle":     {"section": "Section 4", "consent_type": "notice_based", "description": "Notice and consent for asset data"},
}


# ── Inventory Record Management ──────────────────────────────────────────────

def create_inventory_record(
    file_name: str,
    detected_pii_types: List[str],
    data_owner: str,
    storage_location: str,
    security_level: str,
    data_source: str = "unknown",
    pii_counts: Optional[Dict[str, int]] = None,
) -> dict:
    """
    Create or update a personal data inventory record for a scanned file.

    Automatically infers:
        - data_subject_type from detected PII types
        - purpose_of_processing from PII types
        - consent requirements from DPDPA sections
    """
    # Infer data subject types from PII found
    subjects = set()
    for pii_type in detected_pii_types:
        subjects.add(PII_SUBJECT_MAP.get(pii_type, "data_principal"))

    # Infer processing purposes
    purposes = []
    for pii_type in detected_pii_types:
        purpose = PII_PURPOSE_MAP.get(pii_type)
        if purpose and purpose not in purposes:
            purposes.append(purpose)

    # Determine consent requirements
    consent_entries = []
    for pii_type in detected_pii_types:
        req = DPDPA_CONSENT_REQ.get(pii_type)
        if req:
            consent_entries.append({
                "pii_type": pii_type,
                "section": req["section"],
                "consent_type": req["consent_type"],
                "description": req["description"],
            })

    # Determine overall consent status
    has_explicit = any(c["consent_type"] == "explicit" for c in consent_entries)
    has_statutory = any(c["consent_type"] == "statutory" for c in consent_entries)

    if has_explicit or has_statutory:
        consent_status = "requires_verification"
    elif consent_entries:
        consent_status = "notice_based"
    else:
        consent_status = "not_applicable"

    # Calculate DPDPA compliance score (0-100)
    compliance_score = _calculate_compliance_score(
        detected_pii_types, security_level, consent_status
    )

    record = {
        "file_name": file_name,
        "detected_personal_data_types": detected_pii_types,
        "pii_counts": pii_counts or {},
        "data_owner_department": data_owner,
        "storage_location": storage_location,
        "security_level": security_level,
        "data_source": data_source,
        "data_subject_type": sorted(subjects),
        "purpose_of_processing": purposes,
        "consent_status": consent_status,
        "consent_requirements": consent_entries,
        "lawful_basis": _determine_lawful_basis(detected_pii_types),
        "retention_policy": _suggest_retention(detected_pii_types),
        "compliance_score": compliance_score,
        "dpdpa_obligations": _list_obligations(detected_pii_types),
        "created_at": _now(),
        "updated_at": _now(),
    }

    _inventory_store[file_name] = record
    return record


def get_inventory_record(file_name: str) -> Optional[dict]:
    """Retrieve a single inventory record."""
    record = _inventory_store.get(file_name)
    return copy.deepcopy(record) if record else None


def get_all_inventory_records() -> List[dict]:
    """Return all inventory records as a list."""
    return [copy.deepcopy(r) for r in _inventory_store.values()]


def update_consent_status(file_name: str, consent_status: str) -> bool:
    """
    Update the consent status for a file.

    Valid statuses:
        verified        — consent obtained and documented
        pending         — consent collection in progress
        requires_verification — contains PII needing explicit consent
        notice_based    — only needs notice (no explicit consent)
        not_applicable  — no personal data
    """
    record = _inventory_store.get(file_name)
    if not record:
        return False
    record["consent_status"] = consent_status
    record["updated_at"] = _now()
    record["compliance_score"] = _calculate_compliance_score(
        record["detected_personal_data_types"],
        record["security_level"],
        consent_status,
    )
    return True


def update_purpose(file_name: str, purpose: str) -> bool:
    """Add a processing purpose to a file's inventory record."""
    record = _inventory_store.get(file_name)
    if not record:
        return False
    if purpose not in record["purpose_of_processing"]:
        record["purpose_of_processing"].append(purpose)
        record["updated_at"] = _now()
    return True


# ── DPDPA Compliance Helpers ─────────────────────────────────────────────────

def _calculate_compliance_score(
    pii_types: List[str],
    security_level: str,
    consent_status: str,
) -> int:
    """
    Calculate a DPDPA compliance readiness score (0-100).

    Factors:
        - Security classification applied (+25)
        - Consent status verified (+30)
        - Storage segregation active (+20)
        - Purpose documented (+15)
        - Retention policy set (+10)
    """
    score = 0

    # Security classification
    if security_level and security_level != "PUBLIC":
        score += 25

    # Consent status
    consent_scores = {
        "verified": 30,
        "notice_based": 20,
        "pending": 10,
        "requires_verification": 5,
        "not_applicable": 30,
    }
    score += consent_scores.get(consent_status, 0)

    # Storage segregation (assumed active if security level assigned)
    if security_level in ("RESTRICTED", "CONFIDENTIAL", "TOP SECRET"):
        score += 20
    elif security_level == "INTERNAL":
        score += 15
    else:
        score += 10

    # Purpose documented (auto-inferred counts partially)
    if pii_types:
        score += 15

    # Base retention awareness
    score += 10

    return min(score, 100)


def _determine_lawful_basis(pii_types: List[str]) -> str:
    """Determine the DPDPA lawful basis for processing based on PII types."""
    has_statutory = any(
        DPDPA_CONSENT_REQ.get(pt, {}).get("consent_type") == "statutory"
        for pt in pii_types
    )
    has_explicit = any(
        DPDPA_CONSENT_REQ.get(pt, {}).get("consent_type") == "explicit"
        for pt in pii_types
    )

    if has_statutory:
        return "Section 7 — Processing for compliance with law"
    elif has_explicit:
        return "Section 6 — Processing based on explicit consent"
    elif pii_types:
        return "Section 4 — Processing for lawful purpose with notice"
    return "No personal data — N/A"


def _suggest_retention(pii_types: List[str]) -> str:
    """Suggest retention policy based on PII types."""
    critical_types = {"PAN", "Aadhaar", "Passport", "Card", "BankAccount"}
    if critical_types & set(pii_types):
        return "Retain as per statutory requirement; delete upon purpose fulfillment (Section 8(7))"
    elif pii_types:
        return "Retain only for stated purpose; periodic review recommended (Section 8(7))"
    return "Standard retention — no personal data constraints"


def _list_obligations(pii_types: List[str]) -> List[str]:
    """List DPDPA obligations applicable to the detected PII types."""
    obligations = set()

    if pii_types:
        obligations.add("Section 5 — Provide notice before processing personal data")
        obligations.add("Section 8(7) — Erase personal data when purpose fulfilled")
        obligations.add("Section 8(4) — Implement appropriate security safeguards")

    critical_types = {"PAN", "Aadhaar", "Passport", "HealthData"}
    if critical_types & set(pii_types):
        obligations.add("Section 8(1) — Obtain explicit consent for sensitive data")
        obligations.add("Section 8(3) — Ensure data accuracy and completeness")

    financial_types = {"Card", "BankAccount", "IFSC"}
    if financial_types & set(pii_types):
        obligations.add("Section 8 — PCI-DSS and RBI data localisation compliance")

    if "DOB" in pii_types:
        obligations.add("Section 9 — Additional obligations for children's data")

    if "HealthData" in pii_types:
        obligations.add("Section 8(1) — Explicit consent for health/medical data")

    return sorted(obligations)


# ── Summary & Analytics ──────────────────────────────────────────────────────

def inventory_summary() -> dict:
    """
    Return aggregate statistics for the personal data inventory.

    Used by the DPDPA compliance dashboard.
    """
    total = len(_inventory_store)
    by_security = {}
    by_consent = {}
    by_subject = {}
    by_source = {}
    total_pii_types = {}
    compliance_scores = []
    files_with_pii = 0
    files_needing_consent = 0

    for record in _inventory_store.values():
        level = record["security_level"]
        by_security[level] = by_security.get(level, 0) + 1

        consent = record["consent_status"]
        by_consent[consent] = by_consent.get(consent, 0) + 1

        for subj in record["data_subject_type"]:
            by_subject[subj] = by_subject.get(subj, 0) + 1

        src = record["data_source"]
        by_source[src] = by_source.get(src, 0) + 1

        for pt in record["detected_personal_data_types"]:
            total_pii_types[pt] = total_pii_types.get(pt, 0) + 1

        compliance_scores.append(record["compliance_score"])

        if record["detected_personal_data_types"]:
            files_with_pii += 1

        if consent in ("requires_verification", "pending"):
            files_needing_consent += 1

    avg_compliance = (
        round(sum(compliance_scores) / len(compliance_scores))
        if compliance_scores else 0
    )

    return {
        "total_files_cataloged": total,
        "files_with_personal_data": files_with_pii,
        "files_needing_consent": files_needing_consent,
        "by_security_level": by_security,
        "by_consent_status": by_consent,
        "by_data_subject_type": by_subject,
        "by_data_source": by_source,
        "pii_type_distribution": total_pii_types,
        "average_compliance_score": avg_compliance,
        "compliance_rating": (
            "HIGH" if avg_compliance >= 80 else
            "MEDIUM" if avg_compliance >= 50 else
            "LOW"
        ),
    }


def dpdpa_compliance_report() -> dict:
    """
    Generate a DPDPA compliance summary report.

    Returns structured JSON for the frontend dashboard and PDF/CSV export.
    """
    records = get_all_inventory_records()
    summary = inventory_summary()

    # Collect all unique obligations across all files
    all_obligations = set()
    consent_gaps = []
    high_risk_files = []

    for record in records:
        all_obligations.update(record.get("dpdpa_obligations", []))

        if record["consent_status"] in ("requires_verification", "pending"):
            consent_gaps.append({
                "file_name": record["file_name"],
                "consent_status": record["consent_status"],
                "pii_types": record["detected_personal_data_types"],
                "consent_requirements": record["consent_requirements"],
            })

        if record["security_level"] in ("CONFIDENTIAL", "TOP SECRET"):
            high_risk_files.append({
                "file_name": record["file_name"],
                "security_level": record["security_level"],
                "pii_types": record["detected_personal_data_types"],
                "compliance_score": record["compliance_score"],
            })

    return {
        "report_title": "DPDPA Compliance Assessment Report",
        "generated_at": _now(),
        "summary": summary,
        "applicable_obligations": sorted(all_obligations),
        "consent_gaps": consent_gaps,
        "high_risk_files": high_risk_files,
        "recommendations": _generate_recommendations(records, summary),
    }


def _generate_recommendations(records: List[dict], summary: dict) -> List[str]:
    """Generate actionable DPDPA compliance recommendations."""
    recs = []

    if summary["files_needing_consent"] > 0:
        recs.append(
            f"URGENT: {summary['files_needing_consent']} file(s) contain personal data "
            f"requiring consent verification under DPDPA Section 6."
        )

    confidential = summary["by_security_level"].get("CONFIDENTIAL", 0)
    top_secret = summary["by_security_level"].get("TOP SECRET", 0)
    if confidential + top_secret > 0:
        recs.append(
            f"{confidential + top_secret} file(s) classified CONFIDENTIAL or above. "
            f"Ensure encryption at rest and restricted access per Section 8(4)."
        )

    if summary["average_compliance_score"] < 70:
        recs.append(
            "Overall compliance score is below 70%. Review consent collection procedures "
            "and ensure purpose limitation is documented for all datasets."
        )

    if "Aadhaar" in summary.get("pii_type_distribution", {}):
        recs.append(
            "Aadhaar numbers detected. Ensure compliance with Aadhaar Act provisions "
            "and DPDPA Section 8(3) data accuracy requirements."
        )

    if "HealthData" in summary.get("pii_type_distribution", {}):
        recs.append(
            "Health data detected. Explicit consent required under DPDPA Section 8(1). "
            "Verify consent records and implement additional access controls."
        )

    if summary.get("by_data_subject_type", {}).get("citizen", 0) > 0:
        recs.append(
            "Citizen identity data (Aadhaar/Passport) found. Implement data localisation "
            "as required and ensure cross-border transfer compliance per Section 16."
        )

    if not recs:
        recs.append("No critical compliance gaps identified. Continue periodic reviews.")

    return recs


# ── Clear / Reset ────────────────────────────────────────────────────────────

def clear_inventory():
    """Clear all inventory data."""
    _inventory_store.clear()
