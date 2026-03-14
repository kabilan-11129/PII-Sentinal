"""
file_segregation.py — Automated File Segregation by Security Level

Automatically organizes scanned files into security-level folders:

    enterprise_storage/
    ├── public/
    ├── internal/
    ├── restricted/
    └── confidential/

When a file is scanned, it is copied to the appropriate security folder
based on the detected PII classification level.

Security Level Assignment Rules:
    - No PII detected          → PUBLIC
    - Email, Phone, Name, etc. → INTERNAL
    - Financial data (Card, BankAccount, IFSC) → RESTRICTED
    - Government IDs (PAN, Aadhaar, Passport)  → CONFIDENTIAL
"""

import os
import shutil
from typing import Dict, List, Optional, Tuple

from scanner.access_control import (
    PII_SECURITY_LEVEL_MAP,
    SECURITY_LEVELS,
    LEVEL_ACCESS,
    get_security_level_name,
)


# ── Default enterprise storage root ──────────────────────────────────────────
_DEFAULT_STORAGE_ROOT = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "enterprise_storage",
)

# Security level folder names (lowercase for filesystem)
LEVEL_FOLDERS = {
    "PUBLIC": "public",
    "INTERNAL": "internal",
    "RESTRICTED": "restricted",
    "CONFIDENTIAL": "confidential",
    "TOP SECRET": "confidential",  # TOP SECRET files go to confidential folder
}

# ── In-memory segregation log ────────────────────────────────────────────────
_segregation_log: List[dict] = []


def get_storage_root() -> str:
    """Return the enterprise storage root path."""
    return _DEFAULT_STORAGE_ROOT


def ensure_storage_structure(storage_root: Optional[str] = None) -> str:
    """
    Create the enterprise storage folder structure if it doesn't exist.

    Returns the storage root path.
    """
    root = storage_root or _DEFAULT_STORAGE_ROOT
    for folder_name in set(LEVEL_FOLDERS.values()):
        folder_path = os.path.join(root, folder_name)
        os.makedirs(folder_path, exist_ok=True)
    return root


def classify_file_security_level(pii_types: List[str]) -> str:
    """
    Determine the security level for a file based on detected PII types.

    Classification Rules:
        - No PII            → PUBLIC
        - Email/Phone only  → INTERNAL
        - Financial data    → RESTRICTED
        - PAN/Aadhaar       → CONFIDENTIAL

    Parameters:
        pii_types : List of detected PII type names (e.g., ["Email", "PAN"])

    Returns:
        Security level name (PUBLIC, INTERNAL, RESTRICTED, CONFIDENTIAL)
    """
    if not pii_types:
        return "PUBLIC"

    max_level = 1
    for pii_type in pii_types:
        level = PII_SECURITY_LEVEL_MAP.get(pii_type, 2)
        if level > max_level:
            max_level = level

    # Map numeric level to name
    level_name = get_security_level_name(max_level)
    return level_name


def segregate_file(
    source_path: str,
    file_name: str,
    security_level: str,
    storage_root: Optional[str] = None,
    copy_only: bool = True,
) -> Tuple[bool, str, str]:
    """
    Move or copy a file to the appropriate security-level folder.

    Parameters:
        source_path    : Full path to the source file
        file_name      : Name of the file
        security_level : Security classification (PUBLIC/INTERNAL/RESTRICTED/CONFIDENTIAL)
        storage_root   : Override enterprise storage root path
        copy_only      : If True, copy instead of move (preserves original)

    Returns:
        (success: bool, destination_path: str, message: str)
    """
    root = storage_root or _DEFAULT_STORAGE_ROOT
    ensure_storage_structure(root)

    folder_name = LEVEL_FOLDERS.get(security_level, "internal")
    dest_dir = os.path.join(root, folder_name)
    dest_path = os.path.join(dest_dir, file_name)

    # Handle filename collisions by appending a counter
    if os.path.exists(dest_path):
        base, ext = os.path.splitext(file_name)
        counter = 1
        while os.path.exists(dest_path):
            dest_path = os.path.join(dest_dir, f"{base}_{counter}{ext}")
            counter += 1

    try:
        if not os.path.isfile(source_path):
            return False, "", f"Source file not found: {source_path}"

        if copy_only:
            shutil.copy2(source_path, dest_path)
            action = "copied"
        else:
            shutil.move(source_path, dest_path)
            action = "moved"

        # Log the segregation event
        log_entry = {
            "file_name": file_name,
            "source_path": source_path,
            "destination_path": dest_path,
            "security_level": security_level,
            "folder": folder_name,
            "action": action,
            "timestamp": _now(),
        }
        _segregation_log.append(log_entry)

        return True, dest_path, f"File {action} to {security_level.lower()}/{os.path.basename(dest_path)}"

    except PermissionError:
        return False, "", f"Permission denied when segregating {file_name}"
    except Exception as exc:
        return False, "", f"Segregation error: {exc}"


def segregate_scanned_file(
    source_path: str,
    file_name: str,
    pii_counts: Dict[str, int],
    storage_root: Optional[str] = None,
) -> Tuple[str, str, str]:
    """
    Convenience function: classify & segregate a file in one step.

    Parameters:
        source_path  : Full path to the source file
        file_name    : Name of the file
        pii_counts   : Dict of {pii_type: count} from the detection pipeline
        storage_root : Optional override for storage root

    Returns:
        (security_level, destination_path, message)
    """
    # Get PII types that have at least one detection
    pii_types = [pii_type for pii_type, count in pii_counts.items() if count > 0]

    # Classify
    security_level = classify_file_security_level(pii_types)

    # Get authorized roles for this level
    authorized_roles = LEVEL_ACCESS.get(security_level, [])

    # Segregate
    success, dest_path, message = segregate_file(
        source_path=source_path,
        file_name=file_name,
        security_level=security_level,
        storage_root=storage_root,
    )

    if not success:
        dest_path = source_path  # Keep original if segregation failed

    return security_level, dest_path, message


def get_segregation_log() -> List[dict]:
    """Return the segregation log (all file movements)."""
    return list(_segregation_log)


def get_segregation_summary() -> dict:
    """
    Return summary of segregated files by level.

    Returns:
        {
            "total_segregated": N,
            "by_level": { "PUBLIC": N, "INTERNAL": N, ... },
            "recent": [ ... last 10 entries ... ],
        }
    """
    by_level: Dict[str, int] = {}
    for entry in _segregation_log:
        level = entry["security_level"]
        by_level[level] = by_level.get(level, 0) + 1

    return {
        "total_segregated": len(_segregation_log),
        "by_level": by_level,
        "recent": _segregation_log[-10:] if _segregation_log else [],
    }


def get_files_in_level(security_level: str, storage_root: Optional[str] = None) -> List[str]:
    """
    List all files currently in a security-level folder.

    Parameters:
        security_level : PUBLIC, INTERNAL, RESTRICTED, or CONFIDENTIAL
        storage_root   : Optional override for storage root

    Returns:
        List of filenames in the folder.
    """
    root = storage_root or _DEFAULT_STORAGE_ROOT
    folder_name = LEVEL_FOLDERS.get(security_level, "internal")
    folder_path = os.path.join(root, folder_name)

    if not os.path.isdir(folder_path):
        return []

    return [f for f in os.listdir(folder_path) if os.path.isfile(os.path.join(folder_path, f))]


def clear_segregation_log():
    """Clear the segregation log."""
    _segregation_log.clear()


def _now() -> str:
    """Return current timestamp string."""
    from datetime import datetime
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")
