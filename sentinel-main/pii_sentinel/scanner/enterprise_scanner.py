"""
enterprise_scanner.py — Enterprise Data Source Integration for PII Sentinel

Provides a unified interface for scanning enterprise data sources:
  - Email accounts (IMAP) — emails + attachments
  - Cloud storage (S3, Google Drive, Azure, Dropbox)
  - Enterprise folder paths (on-premises shared drives)

Each source scanner:
  1. Authenticates with provided credentials
  2. Discovers files from the source
  3. Sends discovered files through the existing PII scanning pipeline
  4. Returns scan results with origin metadata

Admin Configuration:
  - Credentials are provided per-source
  - Supports batch scanning of all configured sources
"""

import os
import tempfile
from datetime import datetime
from typing import Dict, List, Optional, Tuple

from scanner.file_parser import parse_file
from scanner.pii_detector import detect_all_pii, count_pii, total_pii
from scanner.classifier import classify_all, assess_risk
from scanner.cloud_scanner import scan_cloud
from scanner.imap_scanner import scan_imap_inbox
from scanner.file_segregation import segregate_scanned_file, classify_file_security_level
from scanner.access_control import LEVEL_ACCESS
from scanner.data_lineage import create_lineage_record, record_file_movement
from reports.report_generator import build_rows, infer_data_source, infer_storage_location


# ── Supported file extensions (same as app.py) ──────────────────────────────
ALLOWED_EXTENSIONS = {
    "txt", "log", "md", "csv", "xlsx", "xls", "ods",
    "pdf", "docx", "pptx", "rtf", "odt",
    "json", "xml", "html", "htm", "eml", "msg",
    "zip", "tar", "gz", "tgz",
}

MAX_FILE_SIZE = 1 * 1024 * 1024  # 1 MB per file limit


def _is_supported(filename: str) -> bool:
    """Check if file has a supported extension."""
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def _now() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _run_file_through_pipeline(
    filepath: str,
    filename: str,
    origin_source: str,
    storage_loc: str,
    data_owner: str,
    storage_root: Optional[str] = None,
) -> Optional[dict]:
    """
    Run a single file through the full PII scanning pipeline.

    Pipeline stages:
      1. Text extraction (file_parser)
      2. PII detection (pii_detector)
      3. Classification (classifier)
      4. Security level assignment
      5. File segregation (file_segregation)
      6. Lineage tracking (data_lineage)

    Returns:
        Result dict with all scan details, or None on failure.
    """
    try:
        text = parse_file(filepath)
        if len(text) > 200_000:
            text = text[:200_000]

        pii_results = detect_all_pii(text)
        pii_counts = count_pii(pii_results)
        pii_total_count = total_pii(pii_results)
        classifications = classify_all(pii_results)
        risk_level, risk_reason = assess_risk(pii_results)
        source_type = infer_data_source(filename)
        scan_time = _now()

        rows = build_rows(filename, pii_results, scan_time, data_owner)
        for r in rows:
            r["storage_location"] = storage_loc
            r["data_source"] = origin_source

        # Determine security level and segregate
        security_level, dest_path, seg_message = segregate_scanned_file(
            source_path=filepath,
            file_name=filename,
            pii_counts=pii_counts,
            storage_root=storage_root,
        )

        # Get authorized roles
        pii_types_detected = [pt for pt, c in pii_counts.items() if c > 0]
        authorized_roles = LEVEL_ACCESS.get(security_level, [])

        # Create lineage record
        create_lineage_record(
            file_name=filename,
            origin_source=origin_source,
            original_path=filepath,
            current_path=dest_path,
            detected_pii=pii_types_detected,
            security_level=security_level,
            authorized_roles=authorized_roles,
        )

        # Record movement from origin to segregated folder
        if dest_path != filepath:
            record_file_movement(
                file_name=filename,
                from_path=filepath,
                to_path=dest_path,
                reason=f"Segregated to {security_level} folder",
            )

        fsize = os.path.getsize(filepath) if os.path.isfile(filepath) else 0
        fsize_str = f"{fsize / 1024:.1f} KB" if fsize < 1_048_576 else f"{fsize / 1_048_576:.1f} MB"

        return {
            "rows": rows,
            "detail": {
                "filename": filename,
                "data_source": origin_source,
                "storage_location": storage_loc,
                "data_owner": data_owner,
                "file_size": fsize_str,
                "pii_results": pii_results,
                "pii_counts": pii_counts,
                "pii_total": pii_total_count,
                "classifications": classifications,
                "risk_level": risk_level,
                "risk_reason": risk_reason,
                "scan_time": scan_time,
                "security_level": security_level,
                "segregated_to": dest_path,
                "authorized_roles": authorized_roles,
            },
            "activity": {
                "time": scan_time,
                "filename": filename,
                "risk_level": risk_level,
                "pii_total": pii_total_count,
                "action": f"Enterprise scan ({origin_source}): {filename} — {pii_total_count} PII ({risk_level} risk) → {security_level}",
            },
            "pii_total_count": pii_total_count,
            "security_level": security_level,
        }

    except Exception as exc:
        return None


# ── Enterprise Email Scanner ─────────────────────────────────────────────────

def scan_enterprise_email(
    email_address: str,
    password: str,
    imap_host: str = "imap.gmail.com",
    imap_port: int = 993,
    max_emails: int = 50,
    folder: str = "INBOX",
    data_owner: str = "Enterprise",
    storage_root: Optional[str] = None,
) -> dict:
    """
    Scan enterprise email account for PII in emails and attachments.

    Scans:
      - Email body text
      - Email headers (From, To, Subject)
      - All attachments (extracted and parsed)

    Returns:
        {
            "success": bool,
            "emails_scanned": int,
            "total_pii": int,
            "results": [...],
            "message": str
        }
    """
    try:
        results = scan_imap_inbox(
            email_address=email_address,
            password=password,
            imap_host=imap_host,
            imap_port=imap_port,
            max_emails=max_emails,
            folder=folder,
        )
    except Exception as e:
        return {
            "success": False,
            "emails_scanned": 0,
            "total_pii": 0,
            "results": [],
            "message": f"Email scan error: {e}",
        }

    scan_results = []
    total_pii_found = 0

    for r in results:
        pii_results = r.get("pii_results", {})
        pii_counts = r.get("pii_counts", {})
        pii_total_count = r.get("pii_total", 0)
        risk_level = r.get("risk_level", "LOW")
        risk_reason = r.get("risk_reason", "")
        classifications = r.get("classifications", {})
        filename = r.get("filename", "Unknown Email")
        scan_time = r.get("scan_time", _now())
        storage_loc = r.get("storage_location", f"IMAP: {imap_host}")

        # Determine security level
        pii_types = [pt for pt, c in pii_counts.items() if c > 0]
        security_level = classify_file_security_level(pii_types)
        authorized_roles = LEVEL_ACCESS.get(security_level, [])

        # Create lineage record
        create_lineage_record(
            file_name=filename,
            origin_source=f"Email: {email_address}",
            original_path=f"IMAP/{folder}/{filename}",
            current_path=storage_loc,
            detected_pii=pii_types,
            security_level=security_level,
            authorized_roles=authorized_roles,
        )

        rows = build_rows(filename, pii_results, scan_time, data_owner)
        for row in rows:
            row["storage_location"] = storage_loc

        scan_results.append({
            "rows": rows,
            "detail": {
                "filename": filename,
                "data_source": "Email",
                "storage_location": storage_loc,
                "data_owner": data_owner,
                "file_size": "—",
                "pii_results": pii_results,
                "pii_counts": pii_counts,
                "pii_total": pii_total_count,
                "classifications": classifications,
                "risk_level": risk_level,
                "risk_reason": risk_reason,
                "scan_time": scan_time,
                "security_level": security_level,
                "authorized_roles": authorized_roles,
                "email_from": r.get("from_addr", ""),
                "email_subject": r.get("subject", ""),
            },
            "activity": {
                "time": scan_time,
                "filename": filename,
                "risk_level": risk_level,
                "pii_total": pii_total_count,
                "action": f"Enterprise Email: {filename} — {pii_total_count} PII ({risk_level} risk) → {security_level}",
            },
            "pii_total_count": pii_total_count,
            "security_level": security_level,
        })
        total_pii_found += pii_total_count

    return {
        "success": True,
        "emails_scanned": len(results),
        "total_pii": total_pii_found,
        "results": scan_results,
        "message": f"Enterprise email scan complete — {len(results)} email(s), {total_pii_found} PII items.",
    }


# ── Enterprise Cloud Scanner ────────────────────────────────────────────────

def scan_enterprise_cloud(
    provider: str,
    credentials: dict,
    max_files: int = 100,
    data_owner: str = "Enterprise",
    storage_root: Optional[str] = None,
) -> dict:
    """
    Scan enterprise cloud storage for PII.

    Supports: S3, Google Drive, Azure Blob, Dropbox

    Returns:
        {
            "success": bool,
            "provider": str,
            "files_scanned": int,
            "total_pii": int,
            "results": [...],
            "message": str
        }
    """
    import shutil

    tmp_dir, cloud_files, error = scan_cloud(provider, credentials, max_files=max_files)

    if error:
        return {
            "success": False,
            "provider": provider,
            "files_scanned": 0,
            "total_pii": 0,
            "results": [],
            "message": error,
        }

    scan_results = []
    total_pii_found = 0
    errors = []

    for cf in (cloud_files or []):
        filepath = cf["local"]
        cloud_url = cf["cloud"]
        filename = os.path.basename(filepath)
        storage_loc = f"Cloud ({provider.upper()}): {cloud_url}"

        result = _run_file_through_pipeline(
            filepath=filepath,
            filename=filename,
            origin_source=f"Cloud Storage ({provider.upper()})",
            storage_loc=storage_loc,
            data_owner=data_owner,
            storage_root=storage_root,
        )
        if result:
            scan_results.append(result)
            total_pii_found += result["pii_total_count"]
        else:
            errors.append(filename)

    # Clean up temp directory
    if tmp_dir and os.path.isdir(tmp_dir):
        shutil.rmtree(tmp_dir, ignore_errors=True)

    return {
        "success": True,
        "provider": provider,
        "files_scanned": len(scan_results),
        "total_pii": total_pii_found,
        "results": scan_results,
        "errors": errors,
        "message": f"Enterprise cloud scan ({provider.upper()}) — {len(scan_results)} file(s), {total_pii_found} PII items.",
    }


# ── Enterprise Folder Scanner ───────────────────────────────────────────────

def scan_enterprise_folder(
    folder_path: str,
    recursive: bool = True,
    max_files: int = 100,
    data_owner: str = "Enterprise",
    storage_root: Optional[str] = None,
) -> dict:
    """
    Scan an enterprise folder path for PII in all supported files.

    Returns:
        {
            "success": bool,
            "folder": str,
            "files_scanned": int,
            "total_pii": int,
            "results": [...],
            "message": str
        }
    """
    if not os.path.isdir(folder_path):
        return {
            "success": False,
            "folder": folder_path,
            "files_scanned": 0,
            "total_pii": 0,
            "results": [],
            "message": f"Folder not found: {folder_path}",
        }

    SKIP_DIRS = {
        '.git', '.svn', '.hg', 'node_modules', '__pycache__', '.cache',
        '.vscode', '.idea', 'venv', '.env', 'AppData',
    }

    # Discover files
    discovered = []
    if recursive:
        for root, dirs, files in os.walk(folder_path):
            dirs[:] = [d for d in dirs if not d.startswith('.') and d not in SKIP_DIRS]
            for f in files:
                if f.startswith('.'):
                    continue
                if _is_supported(f):
                    fp = os.path.join(root, f)
                    try:
                        if os.path.getsize(fp) <= MAX_FILE_SIZE:
                            discovered.append(fp)
                    except OSError:
                        pass
                if len(discovered) >= max_files:
                    break
            if len(discovered) >= max_files:
                break
    else:
        try:
            for f in os.listdir(folder_path):
                fp = os.path.join(folder_path, f)
                if os.path.isfile(fp) and not f.startswith('.') and _is_supported(f):
                    try:
                        if os.path.getsize(fp) <= MAX_FILE_SIZE:
                            discovered.append(fp)
                    except OSError:
                        pass
                if len(discovered) >= max_files:
                    break
        except PermissionError:
            return {
                "success": False,
                "folder": folder_path,
                "files_scanned": 0,
                "total_pii": 0,
                "results": [],
                "message": f"Permission denied: {folder_path}",
            }

    scan_results = []
    total_pii_found = 0
    errors = []
    storage_loc = f"Enterprise Folder: {folder_path}"

    for filepath in discovered:
        filename = os.path.basename(filepath)
        result = _run_file_through_pipeline(
            filepath=filepath,
            filename=filename,
            origin_source="Enterprise Folder",
            storage_loc=storage_loc,
            data_owner=data_owner,
            storage_root=storage_root,
        )
        if result:
            scan_results.append(result)
            total_pii_found += result["pii_total_count"]
        else:
            errors.append(filename)

    return {
        "success": True,
        "folder": folder_path,
        "files_found": len(discovered),
        "files_scanned": len(scan_results),
        "total_pii": total_pii_found,
        "results": scan_results,
        "errors": errors,
        "message": f"Enterprise folder scan — {len(scan_results)} file(s), {total_pii_found} PII items.",
    }


# ── Full Enterprise Scan Orchestrator ────────────────────────────────────────

def run_enterprise_scan(
    sources: dict,
    data_owner: str = "Enterprise",
    storage_root: Optional[str] = None,
) -> dict:
    """
    Run a full enterprise scan across all configured sources.

    Parameters:
        sources: {
            "email": { "enabled": bool, "email": str, "password": str, ... },
            "cloud": { "enabled": bool, "provider": str, "credentials": {}, ... },
            "folders": [ { "enabled": bool, "path": str, "recursive": bool, ... } ],
        }
        data_owner   : Owner label for all scanned data
        storage_root : Override for enterprise storage root

    Returns:
        Combined results from all sources.
    """
    all_results = {
        "email": None,
        "cloud": None,
        "folders": [],
    }
    total_files = 0
    total_pii = 0

    # Scan email
    email_cfg = sources.get("email", {})
    if email_cfg.get("enabled"):
        email_result = scan_enterprise_email(
            email_address=email_cfg.get("email", ""),
            password=email_cfg.get("password", ""),
            imap_host=email_cfg.get("imap_host", "imap.gmail.com"),
            imap_port=int(email_cfg.get("imap_port", 993)),
            max_emails=int(email_cfg.get("max_emails", 50)),
            folder=email_cfg.get("folder", "INBOX"),
            data_owner=data_owner,
            storage_root=storage_root,
        )
        all_results["email"] = email_result
        total_files += email_result.get("emails_scanned", 0)
        total_pii += email_result.get("total_pii", 0)

    # Scan cloud
    cloud_cfg = sources.get("cloud", {})
    if cloud_cfg.get("enabled"):
        cloud_result = scan_enterprise_cloud(
            provider=cloud_cfg.get("provider", ""),
            credentials=cloud_cfg.get("credentials", {}),
            max_files=int(cloud_cfg.get("max_files", 100)),
            data_owner=data_owner,
            storage_root=storage_root,
        )
        all_results["cloud"] = cloud_result
        total_files += cloud_result.get("files_scanned", 0)
        total_pii += cloud_result.get("total_pii", 0)

    # Scan folders
    folders_cfg = sources.get("folders", [])
    if isinstance(folders_cfg, dict):
        folders_cfg = [folders_cfg]
    for folder_cfg in folders_cfg:
        if folder_cfg.get("enabled"):
            folder_result = scan_enterprise_folder(
                folder_path=folder_cfg.get("path", ""),
                recursive=folder_cfg.get("recursive", True),
                max_files=int(folder_cfg.get("max_files", 100)),
                data_owner=data_owner,
                storage_root=storage_root,
            )
            all_results["folders"].append(folder_result)
            total_files += folder_result.get("files_scanned", 0)
            total_pii += folder_result.get("total_pii", 0)

    return {
        "success": True,
        "total_files_scanned": total_files,
        "total_pii_detected": total_pii,
        "results": all_results,
        "message": f"Enterprise scan complete — {total_files} item(s), {total_pii} PII items detected.",
    }
