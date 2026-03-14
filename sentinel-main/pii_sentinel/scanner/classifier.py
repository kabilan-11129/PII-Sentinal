"""
classifier.py — Sensitivity classification & file-level risk scoring.

Sensitivity levels (DPDPA aligned):
  LOW    — names, vehicle registrations, IP addresses, general text
  MEDIUM — Email, Phone, DOB, IFSC
  HIGH   — PAN, Aadhaar, Card, Passport, BankAccount, HealthData

Risk scoring for a file:
  CRITICAL — government ID combined with financial data or health data
  HIGH     — any single government ID, financial, or health identifier
  MEDIUM   — contact or routing data only (Phone, DOB, IFSC)
  LOW      — only email addresses, names, IPs, or no PII detected
"""

from typing import Dict, List, Tuple


# ── Sensitivity mapping (aligned with DPDPA data categories) ──────────────────
SENSITIVITY: Dict[str, str] = {
    # MEDIUM — contact & financial routing data
    "Email"      : "MEDIUM",
    "Phone"      : "MEDIUM",
    "DOB"        : "MEDIUM",
    "IFSC"       : "MEDIUM",

    # HIGH — government IDs, financial account data, health identifiers
    "PAN"        : "HIGH",
    "Aadhaar"    : "HIGH",
    "Card"       : "HIGH",
    "Passport"   : "HIGH",
    "BankAccount": "HIGH",
    "HealthData" : "HIGH",

    # LOW — identifiers with lower inherent risk
    "Name"       : "LOW",
    "Vehicle"    : "LOW",
    "IPAddress"  : "LOW",
}


def classify_pii_type(pii_type: str) -> str:
    """Return the DPDPA sensitivity level for a single PII type."""
    return SENSITIVITY.get(pii_type, "LOW")


def classify_all(pii_results: Dict[str, List[str]]) -> Dict[str, str]:
    """
    For every PII type that has at least one detection, return its sensitivity.
    """
    return {
        pii_type: classify_pii_type(pii_type)
        for pii_type, values in pii_results.items()
        if values
    }


def assess_risk(pii_results: Dict[str, List[str]]) -> Tuple[str, str]:
    """
    Determine the overall risk level for a scanned source.

    Returns (risk_level, reason).
    """
    def has(t: str) -> bool:
        return bool(pii_results.get(t))

    has_gov_id   = any(has(t) for t in ("PAN", "Aadhaar", "Passport"))
    has_financial = any(has(t) for t in ("Card", "BankAccount"))
    has_health   = has("HealthData")

    high_types = [t for t in ("PAN", "Aadhaar", "Passport", "Card", "BankAccount", "HealthData") if has(t)]

    # CRITICAL: government/financial ID co-exists with payment card, bank account, or health data
    if (has_gov_id and (has_financial or has_health)) or (has_financial and has_health):
        return "CRITICAL", f"Multiple HIGH-sensitivity identifiers co-present: {', '.join(high_types)}"

    # HIGH: any single government ID, financial identifier, or health data
    if high_types:
        return "HIGH", f"Contains HIGH-sensitivity PII: {', '.join(high_types)}"

    # MEDIUM: contact or financial routing data
    medium = [t for t in ("Phone", "DOB", "IFSC") if has(t)]
    if medium:
        return "MEDIUM", f"Contains MEDIUM-sensitivity PII: {', '.join(medium)}"

    if has("Email"):
        return "LOW", "Contains email addresses only"

    low_ids = [t for t in ("Name", "Vehicle", "IPAddress") if has(t)]
    if low_ids:
        return "LOW", f"Contains low-sensitivity identifiers: {', '.join(low_ids)}"

    return "LOW", "No PII detected"


def risk_color(level: str) -> str:
    """Return a Bootstrap-friendly colour class for the risk badge."""
    return {"CRITICAL": "danger", "HIGH": "danger", "MEDIUM": "warning", "LOW": "success"}.get(
        level, "secondary"
    )


def sensitivity_color(level: str) -> str:
    """Return a Bootstrap colour class for sensitivity badges."""
    return {"HIGH": "danger", "MEDIUM": "warning", "LOW": "success"}.get(level, "secondary")
