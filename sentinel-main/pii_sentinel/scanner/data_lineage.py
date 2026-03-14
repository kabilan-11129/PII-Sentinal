"""
data_lineage.py — Data Lineage Tracking for PII Sentinel Enterprise

Tracks the complete lifecycle of files containing sensitive data:
  - Origin source (email, cloud, local folder, upload)
  - File movement through security-level folders
  - Access history (authorized and denied)
  - Sharing path across departments/roles
  - PII detected and security classifications

Provides functions for:
  - Creating lineage records
  - Recording file movements
  - Logging access attempts
  - Querying lineage history
"""

import copy
from datetime import datetime
from typing import Dict, List, Optional


# ── In-memory lineage store ──────────────────────────────────────────────────
# Key: file_name (str) → lineage record (dict)
_lineage_store: Dict[str, dict] = {}

# Global list of all access attempts (for unauthorized access tracking)
_access_log: List[dict] = []


def _now() -> str:
    """Return current timestamp string."""
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


# ── Lineage Record CRUD ─────────────────────────────────────────────────────

def create_lineage_record(
    file_name: str,
    origin_source: str,
    original_path: str,
    current_path: str,
    detected_pii: List[str],
    security_level: str,
    authorized_roles: List[str],
    sharing_path: Optional[List[str]] = None,
) -> dict:
    """
    Create a new lineage record for a scanned file.

    Parameters:
        file_name        : Name of the file
        origin_source    : Where the file came from (e.g., "HR Email Attachment", "S3 Bucket", "Local Folder")
        original_path    : Original file path or location
        current_path     : Current file path after processing/segregation
        detected_pii     : List of PII types found (e.g., ["Email", "Aadhaar", "PAN"])
        security_level   : Assigned security level (PUBLIC/INTERNAL/RESTRICTED/CONFIDENTIAL/TOP SECRET)
        authorized_roles : Roles that can access this file
        sharing_path     : Departments or roles the file has been shared with

    Returns:
        The created lineage record dict.
    """
    record = {
        "file_name": file_name,
        "origin_source": origin_source,
        "original_path": original_path,
        "current_path": current_path,
        "sharing_path": sharing_path or [],
        "detected_pii": detected_pii,
        "security_level": security_level,
        "authorized_roles": authorized_roles,
        "access_history": [],
        "movement_history": [
            {
                "action": "created",
                "from_path": origin_source,
                "to_path": current_path,
                "timestamp": _now(),
                "details": f"File discovered from {origin_source}",
            }
        ],
        "created_at": _now(),
        "updated_at": _now(),
    }

    _lineage_store[file_name] = record
    return record


def get_lineage_record(file_name: str) -> Optional[dict]:
    """Retrieve the lineage record for a file, or None if not tracked."""
    record = _lineage_store.get(file_name)
    return copy.deepcopy(record) if record else None


def get_all_lineage_records() -> List[dict]:
    """Return all lineage records as a list (deep copies)."""
    return [copy.deepcopy(r) for r in _lineage_store.values()]


def get_lineage_count() -> int:
    """Return number of tracked files."""
    return len(_lineage_store)


# ── File Movement Tracking ───────────────────────────────────────────────────

def record_file_movement(
    file_name: str,
    from_path: str,
    to_path: str,
    reason: str = "",
) -> bool:
    """
    Record a file movement event in the lineage history.

    Example lineage flow:
        HR Email → employee_records.xlsx created
        → Stored in Internal Folder
        → Moved to Confidential Folder

    Returns True if recorded, False if file not in lineage store.
    """
    record = _lineage_store.get(file_name)
    if not record:
        return False

    movement = {
        "action": "moved",
        "from_path": from_path,
        "to_path": to_path,
        "timestamp": _now(),
        "details": reason or f"Moved from {from_path} to {to_path}",
    }
    record["movement_history"].append(movement)
    record["current_path"] = to_path
    record["updated_at"] = _now()
    return True


def update_security_level(
    file_name: str,
    new_level: str,
    new_authorized_roles: List[str],
) -> bool:
    """
    Update the security classification of a tracked file.
    Called when re-scanning reveals new PII or classification changes.
    """
    record = _lineage_store.get(file_name)
    if not record:
        return False

    old_level = record["security_level"]
    record["security_level"] = new_level
    record["authorized_roles"] = new_authorized_roles
    record["updated_at"] = _now()

    if old_level != new_level:
        record["movement_history"].append({
            "action": "reclassified",
            "from_path": record["current_path"],
            "to_path": record["current_path"],
            "timestamp": _now(),
            "details": f"Security level changed: {old_level} → {new_level}",
        })

    return True


def update_sharing_path(file_name: str, shared_with: str) -> bool:
    """
    Record that a file has been shared with a department or role.

    Parameters:
        file_name   : The tracked file
        shared_with : Department or role name (e.g., "HR", "Finance", "Admin")
    """
    record = _lineage_store.get(file_name)
    if not record:
        return False

    if shared_with not in record["sharing_path"]:
        record["sharing_path"].append(shared_with)
        record["updated_at"] = _now()
        record["movement_history"].append({
            "action": "shared",
            "from_path": record["current_path"],
            "to_path": record["current_path"],
            "timestamp": _now(),
            "details": f"Shared with {shared_with}",
        })
    return True


# ── Access History Tracking ──────────────────────────────────────────────────

def log_access_attempt(
    file_name: str,
    user: str,
    role: str,
    status: str,
    details: str = "",
) -> dict:
    """
    Log an access attempt (AUTHORIZED or DENIED) for a tracked file.

    Parameters:
        file_name : The file being accessed
        user      : Username attempting access
        role      : Role of the user (Employee, Manager, HR, Finance, Admin)
        status    : "AUTHORIZED" or "DENIED"
        details   : Optional additional details

    Returns:
        The access log entry dict.
    """
    entry = {
        "file_name": file_name,
        "user": user,
        "role": role,
        "status": status,
        "timestamp": _now(),
        "details": details or f"{status}: {user} ({role}) accessed {file_name}",
    }

    # Add to file's lineage record if tracked
    record = _lineage_store.get(file_name)
    if record:
        record["access_history"].append({
            "user": user,
            "role": role,
            "status": status,
            "timestamp": _now(),
        })
        record["updated_at"] = _now()

        # Update sharing path on authorized access
        if status == "AUTHORIZED" and role not in record["sharing_path"]:
            record["sharing_path"].append(role)

    # Always add to global access log
    _access_log.append(entry)
    return entry


def get_access_history(file_name: str) -> List[dict]:
    """Get all access attempts for a specific file."""
    record = _lineage_store.get(file_name)
    if record:
        return copy.deepcopy(record["access_history"])
    return []


def get_all_access_logs() -> List[dict]:
    """Return all access attempts across all files."""
    return copy.deepcopy(_access_log)


def get_unauthorized_attempts() -> List[dict]:
    """Return all DENIED access attempts."""
    return [copy.deepcopy(e) for e in _access_log if e["status"] == "DENIED"]


def get_movement_history(file_name: str) -> List[dict]:
    """Get the complete movement/sharing history for a file."""
    record = _lineage_store.get(file_name)
    if record:
        return copy.deepcopy(record["movement_history"])
    return []


# ── Summary & Analytics ──────────────────────────────────────────────────────

def lineage_summary() -> dict:
    """
    Return aggregate lineage statistics.

    Returns:
        {
            "total_tracked_files": N,
            "by_security_level": { "PUBLIC": N, ... },
            "by_origin_source": { "Email": N, ... },
            "total_movements": N,
            "total_access_attempts": N,
            "total_unauthorized": N,
            "recent_movements": [ ... last 10 ... ],
            "recent_access": [ ... last 10 ... ],
        }
    """
    by_level = {}
    by_origin = {}
    total_movements = 0

    for record in _lineage_store.values():
        level = record["security_level"]
        by_level[level] = by_level.get(level, 0) + 1

        origin = record["origin_source"]
        by_origin[origin] = by_origin.get(origin, 0) + 1

        total_movements += len(record["movement_history"])

    unauthorized = [e for e in _access_log if e["status"] == "DENIED"]

    # Get recent movements across all files
    all_movements = []
    for record in _lineage_store.values():
        for m in record["movement_history"]:
            all_movements.append({**m, "file_name": record["file_name"]})
    all_movements.sort(key=lambda x: x["timestamp"], reverse=True)

    return {
        "total_tracked_files": len(_lineage_store),
        "by_security_level": by_level,
        "by_origin_source": by_origin,
        "total_movements": total_movements,
        "total_access_attempts": len(_access_log),
        "total_unauthorized": len(unauthorized),
        "recent_movements": all_movements[:10],
        "recent_access": _access_log[-10:] if _access_log else [],
    }


# ── Clear / Reset ───────────────────────────────────────────────────────────

def clear_lineage():
    """Clear all lineage data (for testing or reset)."""
    _lineage_store.clear()
    _access_log.clear()
