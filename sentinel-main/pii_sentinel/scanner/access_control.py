"""
access_control.py — Role-Based Data Access Control for PII Sentinel

Maps detected PII types to security classification levels (1-5 scale) and determines
which enterprise roles are allowed to access each data item.

Security Levels: 1 (PUBLIC) → 2 (INTERNAL) → 3 (RESTRICTED) → 4 (CONFIDENTIAL) → 5 (TOP SECRET)
"""

# ── Enterprise Roles ───────────────────────────────────────────────────────────
ROLES = ["Employee", "Manager", "HR", "Finance", "Admin"]

# ── Security Levels (1-5 scale, 1=lowest, 5=highest) ──────────────────────────
SECURITY_LEVELS = {
    1: "PUBLIC",
    2: "INTERNAL",
    3: "RESTRICTED",
    4: "CONFIDENTIAL",
    5: "TOP SECRET",
}

LEVELS = ["PUBLIC", "INTERNAL", "RESTRICTED", "CONFIDENTIAL", "TOP SECRET"]

# ── Role Clearance Levels (minimum security level each role can access) ───────
ROLE_CLEARANCE = {
    "Employee": 2,   # Can access: PUBLIC (1), INTERNAL (2)
    "Manager":  3,   # Can access: PUBLIC, INTERNAL, RESTRICTED (3)
    "HR":       4,   # Can access: PUBLIC, INTERNAL, RESTRICTED, CONFIDENTIAL (4)
    "Finance":  4,   # Can access: PUBLIC, INTERNAL, RESTRICTED, CONFIDENTIAL (4)
    "Admin":    5,   # Can access: ALL levels (1-5)
}

# ── Which roles can access each level ─────────────────────────────────────────
LEVEL_ACCESS = {
    "PUBLIC":       ["Employee", "Manager", "HR", "Finance", "Admin"],
    "INTERNAL":     ["Employee", "Manager", "HR", "Finance", "Admin"],
    "RESTRICTED":   ["Manager", "HR", "Finance", "Admin"],
    "CONFIDENTIAL": ["HR", "Finance", "Admin"],
    "TOP SECRET":   ["Admin"],
}

# ── PII type → Security Level (1-5) mapping ────────────────────────────────────
PII_SECURITY_LEVEL_MAP = {
    # Level 1 - PUBLIC (no PII - placeholder)
    # Level 2 - INTERNAL — general identifiers
    "Email":      2,
    "Phone":      2,
    "Name":       2,
    "DOB":        2,
    "IPAddress":  2,
    "Vehicle":    2,
    # Level 3 - RESTRICTED — financial & health
    "Card":         3,
    "IFSC":         3,
    "BankAccount":  3,
    "HealthData":   3,
    # Level 4 - CONFIDENTIAL — national IDs
    "PAN":       4,
    "Aadhaar":   4,
    "Passport":  4,
    # Level 5 - TOP SECRET — highly sensitive combinations
    # (Automatically assigned if file contains multiple L4 items)
}

# Legacy mapping for backward compatibility
PII_SECURITY_MAP = {
    "Email":      "INTERNAL",
    "Phone":      "INTERNAL",
    "Name":       "INTERNAL",
    "DOB":        "INTERNAL",
    "IPAddress":  "INTERNAL",
    "Vehicle":    "INTERNAL",
    "Card":         "RESTRICTED",
    "IFSC":         "RESTRICTED",
    "BankAccount":  "RESTRICTED",
    "HealthData":   "RESTRICTED",
    "PAN":       "CONFIDENTIAL",
    "Aadhaar":   "CONFIDENTIAL",
    "Passport":  "CONFIDENTIAL",
}

# ── UI/Display metadata per level ─────────────────────────────────────────────
LEVEL_META = {
    "PUBLIC":       {"color": "#22c55e", "icon": "bi-globe",                      "order": 0, "level": 1},
    "INTERNAL":     {"color": "#06b6d4", "icon": "bi-building",                   "order": 1, "level": 2},
    "RESTRICTED":   {"color": "#f59e0b", "icon": "bi-exclamation-triangle-fill",  "order": 2, "level": 3},
    "CONFIDENTIAL": {"color": "#ef4444", "icon": "bi-shield-lock-fill",           "order": 3, "level": 4},
    "TOP SECRET":   {"color": "#dc2626", "icon": "bi-lock-fill",                  "order": 4, "level": 5},
}


# ── Helper functions ───────────────────────────────────────────────────────────

def get_security_level_numeric(pii_type: str) -> int:
    """Return numeric security level (1-5) for a given PII type (defaults to 2)."""
    return PII_SECURITY_LEVEL_MAP.get(pii_type, 2)


def get_security_level_name(level: int) -> str:
    """Convert numeric level (1-5) to name."""
    return SECURITY_LEVELS.get(level, "INTERNAL")


def classify_pii_security(pii_type: str) -> str:
    """Return security level name for a given PII type (defaults to INTERNAL)."""
    return PII_SECURITY_MAP.get(pii_type, "INTERNAL")


def get_allowed_roles(security_level: str) -> list:
    """Return list of roles allowed to access a security level."""
    return LEVEL_ACCESS.get(security_level, ROLES[:])


def get_allowed_roles_by_level(level: int) -> list:
    """Return roles that can access a given numeric security level."""
    return [role for role, clearance in ROLE_CLEARANCE.items() if clearance >= level]


def calculate_file_security_level(pii_counts: dict) -> tuple:
    """
    Calculate the overall security level for a file based on PII types found.

    Returns: (level_int, level_name)

    Logic:
    - If file contains 3+ CONFIDENTIAL items (level 4), escalate to TOP SECRET (level 5)
    - Otherwise, use the highest level among all detected PII types
    """
    if not pii_counts:
        return (1, "PUBLIC")

    levels = [get_security_level_numeric(pii_type) for pii_type in pii_counts.keys() if pii_counts[pii_type] > 0]
    if not levels:
        return (1, "PUBLIC")

    max_level = max(levels)

    # Escalation rule: 3+ CONFIDENTIAL items → TOP SECRET
    confidential_count = sum(1 for pii_type in pii_counts.keys()
                             if get_security_level_numeric(pii_type) == 4 and pii_counts[pii_type] > 0)
    if confidential_count >= 3:
        return (5, "TOP SECRET")

    return (max_level, get_security_level_name(max_level))


def check_access(user_role: str, security_level: str) -> dict:
    """
    Check whether a given role is authorized to access a given security level.

    Parameters:
        user_role      : One of Employee, Manager, HR, Finance, Admin
        security_level : One of PUBLIC, INTERNAL, RESTRICTED, CONFIDENTIAL, TOP SECRET

    Returns:
        {
            "user_role": str,
            "security_level": str,
            "authorized": bool,
            "message": "ACCESS GRANTED" | "ACCESS DENIED",
            "reason": str
        }

    Access Policy:
        Employee → PUBLIC, INTERNAL
        Manager  → PUBLIC, INTERNAL, RESTRICTED
        HR       → PUBLIC, INTERNAL, RESTRICTED, CONFIDENTIAL
        Finance  → PUBLIC, INTERNAL, RESTRICTED, CONFIDENTIAL
        Admin    → Full access (all levels)
    """
    if user_role not in ROLES:
        return {
            "user_role": user_role,
            "security_level": security_level,
            "authorized": False,
            "message": "ACCESS DENIED",
            "reason": f"Unknown role: {user_role}",
        }

    if security_level not in LEVELS:
        return {
            "user_role": user_role,
            "security_level": security_level,
            "authorized": False,
            "message": "ACCESS DENIED",
            "reason": f"Unknown security level: {security_level}",
        }

    allowed_roles = LEVEL_ACCESS.get(security_level, [])
    authorized = user_role in allowed_roles

    if authorized:
        return {
            "user_role": user_role,
            "security_level": security_level,
            "authorized": True,
            "message": "ACCESS GRANTED",
            "reason": f"{user_role} has clearance for {security_level} data",
        }
    else:
        return {
            "user_role": user_role,
            "security_level": security_level,
            "authorized": False,
            "message": "ACCESS DENIED",
            "reason": f"{user_role} does not have clearance for {security_level} data",
        }


def build_access_map(file_details: list) -> list:
    """
    Build an access-map entry for every (file, pii_type) pair found in
    file_details (the in-memory scan_store list in app.py).

    Returns a flat list of dicts:
        {file_name, source_type, storage_location, data_owner,
         pii_type, pii_count, security_level, security_level_num (1-5),
         allowed_roles, denied_roles}
    """
    entries = []
    for f in file_details:
        fname     = f.get("file_name", "Unknown")
        src_type  = f.get("source_type", "upload")
        storage   = f.get("storage_location", "Local")
        owner     = f.get("data_owner", "Unknown")
        pii_counts = f.get("pii_counts", {})

        for pii_type, count in pii_counts.items():
            if count == 0:
                continue
            level         = classify_pii_security(pii_type)
            level_num     = get_security_level_numeric(pii_type)
            allowed       = get_allowed_roles_by_level(level_num)
            denied        = [r for r in ROLES if r not in allowed]
            entries.append({
                "file_name":          fname,
                "source_type":        src_type,
                "storage_location":   storage,
                "data_owner":         owner,
                "pii_type":           pii_type,
                "pii_count":          count,
                "security_level":     level,
                "security_level_num": level_num,
                "allowed_roles":      allowed,
                "denied_roles":       denied,
            })

    # Sort: TOP SECRET first (5), then CONFIDENTIAL (4), RESTRICTED (3), INTERNAL (2), PUBLIC (1)
    entries.sort(key=lambda e: -e["security_level_num"])
    return entries


def access_summary(access_entries: list) -> dict:
    """
    Aggregate counts by security level and role-access matrix.

    Returns:
        {
          "by_level":  {"CONFIDENTIAL": N, "RESTRICTED": N, ...},
          "by_role":   {"Admin": N, "HR": N, ...},   # files accessible
          "total":     N
        }
    """
    by_level = {lv: 0 for lv in LEVELS}
    by_role  = {r: 0 for r in ROLES}

    # Track unique (file, pii_type) pairs to avoid double-counting
    seen_level = {}  # level -> set of file_names
    seen_role  = {}  # role  -> set of file_names

    for e in access_entries:
        lv   = e["security_level"]
        fn   = e["file_name"]
        seen_level.setdefault(lv, set()).add(fn)
        for role in e["allowed_roles"]:
            seen_role.setdefault(role, set()).add(fn)

    for lv, files in seen_level.items():
        by_level[lv] = len(files)
    for role, files in seen_role.items():
        by_role[role] = len(files)

    return {
        "by_level": by_level,
        "by_role":  by_role,
        "total":    len({e["file_name"] for e in access_entries}),
    }
