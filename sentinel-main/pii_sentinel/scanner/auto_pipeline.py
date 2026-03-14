"""
auto_pipeline.py — Automated Enterprise Scan Pipeline Orchestrator

Receives parsed configuration from config_parser.py and automatically
executes the full scanning pipeline across all configured data sources:

    1. Parse config file → extract credentials
    2. Identify data sources (email, cloud, folder, database)
    3. Connect to each service
    4. Scan discovered files
    5. Run PII detection (pii_detector)
    6. Classify sensitivity (classifier)
    7. Segregate files (file_segregation)
    8. Track lineage (data_lineage)

Provides real-time status updates via an in-memory pipeline state
that the frontend can poll via /api/scan-status.
"""

import os
import sqlite3
import threading
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeoutError
from datetime import datetime
from typing import Dict, List, Optional

from scanner.file_parser import parse_file
from scanner.pii_detector import detect_all_pii, count_pii, total_pii
from scanner.classifier import classify_all, assess_risk
from scanner.access_control import LEVEL_ACCESS
from scanner.data_lineage import create_lineage_record, record_file_movement
from scanner.file_segregation import (
    segregate_scanned_file,
    classify_file_security_level,
)
from reports.report_generator import build_rows, infer_data_source, infer_storage_location


# ── Constants ────────────────────────────────────────────────────────────────
ALLOWED_EXTENSIONS = {
    "txt", "log", "md", "csv", "xlsx", "xls", "ods",
    "pdf", "docx", "pptx", "rtf", "odt",
    "json", "xml", "html", "htm", "eml", "msg",
    "zip", "tar", "gz", "tgz",
}
MAX_FILE_SIZE = 1 * 1024 * 1024  # 1 MB
PER_FILE_TIMEOUT = 15  # seconds

SKIP_DIRS = {
    '.git', '.svn', '.hg', 'node_modules', '__pycache__', '.cache',
    '.vscode', '.idea', 'venv', '.env', 'AppData', 'Application Data',
    'Local Settings', 'Temporary Internet Files',
}


def _now() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _is_supported(filename: str) -> bool:
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


# ── Pipeline State ───────────────────────────────────────────────────────────

class PipelineState:
    """Thread-safe pipeline execution state for frontend polling."""

    def __init__(self):
        self._lock = threading.Lock()
        self.reset()

    def reset(self):
        with self._lock if hasattr(self, '_lock') else _DummyLock():
            self.status = "idle"               # idle | running | completed | failed
            self.current_stage = ""
            self.stages_completed = []
            self.sources_detected = {}
            self.total_sources = 0
            self.sources_processed = 0
            self.files_scanned = 0
            self.total_pii_detected = 0
            self.security_summary = {}
            self.lineage_count = 0
            self.errors = []
            self.message = ""
            self.started_at = ""
            self.completed_at = ""
            self.progress_log = []
            self.scan_results = []

    def update(self, **kwargs):
        with self._lock:
            for k, v in kwargs.items():
                setattr(self, k, v)

    def add_log(self, msg: str):
        with self._lock:
            self.progress_log.append({
                "time": _now(),
                "message": msg,
            })

    def complete_stage(self, stage: str):
        with self._lock:
            if stage not in self.stages_completed:
                self.stages_completed.append(stage)

    def to_dict(self) -> dict:
        with self._lock:
            return {
                "status": self.status,
                "current_stage": self.current_stage,
                "stages_completed": list(self.stages_completed),
                "sources_detected": dict(self.sources_detected),
                "total_sources": self.total_sources,
                "sources_processed": self.sources_processed,
                "files_scanned": self.files_scanned,
                "total_pii_detected": self.total_pii_detected,
                "security_summary": dict(self.security_summary),
                "lineage_count": self.lineage_count,
                "errors": list(self.errors),
                "message": self.message,
                "started_at": self.started_at,
                "completed_at": self.completed_at,
                "progress_log": list(self.progress_log),
            }


class _DummyLock:
    def __enter__(self): return self
    def __exit__(self, *a): pass


# Global pipeline state instance
pipeline_state = PipelineState()


# ── File Processing Pipeline ─────────────────────────────────────────────────

def _process_single_file(
    filepath: str,
    filename: str,
    origin_source: str,
    storage_loc: str,
    data_owner: str,
    storage_root: str,
) -> Optional[dict]:
    """
    Run a single file through the full PII pipeline.

    Stages: parse → detect → classify → segregate → lineage
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

        # Segregate file
        security_level, dest_path, seg_msg = segregate_scanned_file(
            source_path=filepath,
            file_name=filename,
            pii_counts=pii_counts,
            storage_root=storage_root,
        )

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

        if dest_path != filepath:
            record_file_movement(
                file_name=filename,
                from_path=filepath,
                to_path=dest_path,
                reason=f"Auto-segregated to {security_level} folder",
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
                "authorized_roles": authorized_roles,
                "segregated_to": dest_path,
            },
            "activity": {
                "time": scan_time,
                "filename": filename,
                "risk_level": risk_level,
                "pii_total": pii_total_count,
                "action": f"Config scan ({origin_source}): {filename} — {pii_total_count} PII ({risk_level} risk) → {security_level}",
            },
            "pii_total_count": pii_total_count,
            "security_level": security_level,
        }
    except Exception:
        return None


# ── Source Scanners ──────────────────────────────────────────────────────────

def _scan_email_source(
    email_cfg: dict,
    data_owner: str,
    storage_root: str,
    scan_store: list,
    file_details: list,
    scan_activity: list,
) -> dict:
    """Scan an email source via IMAP."""
    from scanner.imap_scanner import scan_imap_inbox

    email_addr = email_cfg["email"]
    password = email_cfg["password"]
    imap_host = email_cfg.get("imap_host", "imap.gmail.com")
    max_emails = int(email_cfg.get("max_emails", 50))
    folder = email_cfg.get("folder", "INBOX")

    try:
        results = scan_imap_inbox(
            email_address=email_addr,
            password=password,
            imap_host=imap_host,
            imap_port=int(email_cfg.get("imap_port", 993)),
            max_emails=max_emails,
            folder=folder,
        )
    except Exception as e:
        return {"success": False, "message": str(e), "scanned": 0, "pii": 0}

    scanned = 0
    total_pii_found = 0

    for r in results:
        pii_results = r.get("pii_results", {})
        pii_counts = r.get("pii_counts", {})
        pii_total_count = r.get("pii_total", 0)
        risk_level = r.get("risk_level", "LOW")
        classifications = r.get("classifications", {})
        filename = r.get("filename", "Unknown Email")
        scan_time = r.get("scan_time", _now())
        storage_loc = r.get("storage_location", f"IMAP: {imap_host}")

        pii_types = [pt for pt, c in pii_counts.items() if c > 0]
        security_level = classify_file_security_level(pii_types)
        authorized_roles = LEVEL_ACCESS.get(security_level, [])

        create_lineage_record(
            file_name=filename,
            origin_source=f"Email: {email_addr}",
            original_path=f"IMAP/{folder}/{filename}",
            current_path=storage_loc,
            detected_pii=pii_types,
            security_level=security_level,
            authorized_roles=authorized_roles,
        )

        rows = build_rows(filename, pii_results, scan_time, data_owner)
        for row in rows:
            row["storage_location"] = storage_loc
        scan_store.extend(rows)

        file_details.append({
            "filename": filename,
            "data_source": f"Email ({email_addr})",
            "storage_location": storage_loc,
            "data_owner": data_owner,
            "file_size": "—",
            "pii_results": pii_results,
            "pii_counts": pii_counts,
            "pii_total": pii_total_count,
            "classifications": classifications,
            "risk_level": risk_level,
            "risk_reason": r.get("risk_reason", ""),
            "scan_time": scan_time,
            "security_level": security_level,
            "authorized_roles": authorized_roles,
        })

        scan_activity.append({
            "time": scan_time,
            "filename": filename,
            "risk_level": risk_level,
            "pii_total": pii_total_count,
            "action": f"Config scan (Email): {filename} — {pii_total_count} PII ({risk_level} risk)",
        })

        scanned += 1
        total_pii_found += pii_total_count

    return {"success": True, "scanned": scanned, "pii": total_pii_found}


def _scan_folder_source(
    folder_cfg: dict,
    data_owner: str,
    storage_root: str,
    scan_store: list,
    file_details: list,
    scan_activity: list,
) -> dict:
    """Scan a local folder source."""
    folder_path = folder_cfg["path"]
    max_files = int(folder_cfg.get("max_files", 100))
    recursive = folder_cfg.get("recursive", True)

    if not os.path.isdir(folder_path):
        return {"success": False, "message": f"Folder not found: {folder_path}", "scanned": 0, "pii": 0}

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
            return {"success": False, "message": f"Permission denied: {folder_path}", "scanned": 0, "pii": 0}

    scanned = 0
    total_pii_found = 0
    storage_loc = f"Enterprise Folder: {folder_path}"

    with ThreadPoolExecutor(max_workers=min(4, len(discovered) or 1)) as pool:
        def _process(fp):
            return _process_single_file(
                filepath=fp,
                filename=os.path.basename(fp),
                origin_source="Enterprise Folder",
                storage_loc=storage_loc,
                data_owner=data_owner,
                storage_root=storage_root,
            )

        futures = {pool.submit(_process, fp): fp for fp in discovered}
        for future in futures:
            try:
                result = future.result(timeout=PER_FILE_TIMEOUT)
                if result:
                    scan_store.extend(result["rows"])
                    file_details.append(result["detail"])
                    scan_activity.append(result["activity"])
                    scanned += 1
                    total_pii_found += result["pii_total_count"]
            except (FuturesTimeoutError, Exception):
                pass

    return {"success": True, "scanned": scanned, "pii": total_pii_found}


def _scan_database_source(
    db_cfg: dict,
    data_owner: str,
    storage_root: str,
    scan_store: list,
    file_details: list,
    scan_activity: list,
) -> dict:
    """Scan a SQLite database source."""
    db_path = db_cfg.get("db_path", "")
    row_limit = int(db_cfg.get("row_limit", 5000))

    if not db_path or not os.path.isfile(db_path):
        return {"success": False, "message": f"Database not found: {db_path}", "scanned": 0, "pii": 0}

    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")
        tables = [row[0] for row in cursor.fetchall()]
    except Exception as e:
        return {"success": False, "message": str(e), "scanned": 0, "pii": 0}

    if not tables:
        conn.close()
        return {"success": True, "scanned": 0, "pii": 0, "message": "No tables found"}

    db_name = os.path.basename(db_path)
    storage_loc = f"SQLite: {db_path}"
    scanned = 0
    total_pii_found = 0

    for table in tables:
        try:
            cursor.execute(f'SELECT * FROM "{table}" LIMIT {row_limit}')  # noqa: S608
            db_rows = cursor.fetchall()
            col_names = [desc[0] for desc in cursor.description] if cursor.description else []
            row_count = len(db_rows)

            text_lines = [" | ".join(col_names)]
            for row in db_rows:
                text_lines.append(" | ".join(str(v) for v in row if v is not None))
            text = "\n".join(text_lines)

            pii_results = detect_all_pii(text)
            pii_counts = count_pii(pii_results)
            pii_total_count = total_pii(pii_results)
            classifications = classify_all(pii_results)
            risk_level, risk_reason = assess_risk(pii_results)

            virtual_name = f"{db_name}::{table}"
            scan_time = _now()
            rows = build_rows(virtual_name, pii_results, scan_time, data_owner)
            for r in rows:
                r["storage_location"] = storage_loc
                r["data_source"] = "SQLite Database"
            scan_store.extend(rows)

            pii_types = [pt for pt, c in pii_counts.items() if c > 0]
            security_level = classify_file_security_level(pii_types)
            authorized_roles = LEVEL_ACCESS.get(security_level, [])

            create_lineage_record(
                file_name=virtual_name,
                origin_source="Database",
                original_path=db_path,
                current_path=storage_loc,
                detected_pii=pii_types,
                security_level=security_level,
                authorized_roles=authorized_roles,
            )

            file_details.append({
                "filename": virtual_name,
                "data_source": "SQLite Database",
                "storage_location": storage_loc,
                "data_owner": data_owner,
                "file_size": f"{row_count} rows",
                "pii_results": pii_results,
                "pii_counts": pii_counts,
                "pii_total": pii_total_count,
                "classifications": classifications,
                "risk_level": risk_level,
                "risk_reason": risk_reason,
                "scan_time": scan_time,
                "security_level": security_level,
                "authorized_roles": authorized_roles,
            })

            scan_activity.append({
                "time": scan_time,
                "filename": virtual_name,
                "risk_level": risk_level,
                "pii_total": pii_total_count,
                "action": f"Config scan (DB): {table} ({row_count} rows) — {pii_total_count} PII ({risk_level} risk)",
            })

            scanned += 1
            total_pii_found += pii_total_count
        except Exception:
            pass

    conn.close()
    return {"success": True, "scanned": scanned, "pii": total_pii_found}


def _scan_cloud_source(
    cloud_cfg: dict,
    data_owner: str,
    storage_root: str,
    scan_store: list,
    file_details: list,
    scan_activity: list,
) -> dict:
    """Scan a cloud storage source."""
    import shutil
    from scanner.cloud_scanner import scan_cloud

    provider = cloud_cfg["provider"]
    credentials = cloud_cfg["credentials"]
    max_files = int(cloud_cfg.get("max_files", 100))

    tmp_dir, cloud_files, error = scan_cloud(provider, credentials, max_files=max_files)

    if error:
        return {"success": False, "message": error, "scanned": 0, "pii": 0}

    scanned = 0
    total_pii_found = 0

    for cf in (cloud_files or []):
        filepath = cf["local"]
        cloud_url = cf["cloud"]
        filename = os.path.basename(filepath)
        storage_loc = f"Cloud ({provider.upper()}): {cloud_url}"

        result = _process_single_file(
            filepath=filepath,
            filename=filename,
            origin_source=f"Cloud Storage ({provider.upper()})",
            storage_loc=storage_loc,
            data_owner=data_owner,
            storage_root=storage_root,
        )
        if result:
            scan_store.extend(result["rows"])
            file_details.append(result["detail"])
            scan_activity.append(result["activity"])
            scanned += 1
            total_pii_found += result["pii_total_count"]

    if tmp_dir and os.path.isdir(tmp_dir):
        shutil.rmtree(tmp_dir, ignore_errors=True)

    return {"success": True, "scanned": scanned, "pii": total_pii_found}


# ── Main Pipeline Orchestrator ───────────────────────────────────────────────

PIPELINE_STAGES = [
    "config_parsed",
    "sources_identified",
    "scanning_emails",
    "scanning_cloud",
    "scanning_folders",
    "scanning_databases",
    "pii_detection",
    "classification",
    "segregation",
    "lineage_tracking",
    "completed",
]


def run_automated_pipeline(
    pipeline_config: dict,
    data_owner: str,
    storage_root: str,
    scan_store: list,
    file_details: list,
    scan_activity: list,
) -> dict:
    """
    Execute the full automated scanning pipeline.

    This is the main orchestrator that:
    1. Takes parsed configuration from config_parser
    2. Iterates through each source type
    3. Runs the full PII pipeline on each discovered file
    4. Updates pipeline_state for frontend polling

    Parameters:
        pipeline_config : Output from config_parser.build_pipeline_config()
        data_owner      : Label for data ownership
        storage_root    : Enterprise storage root path
        scan_store      : In-memory report rows list (app.py)
        file_details    : In-memory file details list (app.py)
        scan_activity   : In-memory activity log list (app.py)

    Returns:
        Final pipeline result dict with all statistics.
    """
    pipeline_state.reset()
    pipeline_state.update(
        status="running",
        started_at=_now(),
        message="Pipeline started — parsing configuration...",
    )

    sources = pipeline_config.get("sources", {})
    total_files = 0
    total_pii = 0
    source_results = {}
    security_counts = {}

    # Stage 1: Config parsed
    pipeline_state.update(current_stage="config_parsed")
    pipeline_state.add_log("Configuration file parsed successfully")
    pipeline_state.complete_stage("config_parsed")

    # Stage 2: Source identification
    pipeline_state.update(current_stage="sources_identified")
    detected = {}
    if sources.get("email", {}).get("enabled"):
        accounts = sources["email"].get("accounts", [])
        detected["email"] = len(accounts)
    if sources.get("cloud", {}).get("enabled"):
        providers = sources["cloud"].get("providers", [])
        detected["cloud"] = len(providers)
    if sources.get("folders"):
        detected["folder"] = len(sources["folders"])
    if sources.get("databases"):
        detected["database"] = len(sources["databases"])

    total_sources = sum(detected.values())
    pipeline_state.update(
        sources_detected=detected,
        total_sources=total_sources,
        message=f"Identified {total_sources} data source(s)",
    )
    pipeline_state.add_log(f"Detected sources: {detected}")
    pipeline_state.complete_stage("sources_identified")

    processed = 0

    # Stage 3: Scan email sources
    if sources.get("email", {}).get("enabled"):
        pipeline_state.update(current_stage="scanning_emails")
        pipeline_state.add_log("Scanning email sources...")

        for account in sources["email"].get("accounts", []):
            result = _scan_email_source(
                email_cfg=account,
                data_owner=data_owner,
                storage_root=storage_root,
                scan_store=scan_store,
                file_details=file_details,
                scan_activity=scan_activity,
            )
            source_results[f"email_{account['email']}"] = result
            total_files += result.get("scanned", 0)
            total_pii += result.get("pii", 0)
            processed += 1
            pipeline_state.update(
                sources_processed=processed,
                files_scanned=total_files,
                total_pii_detected=total_pii,
            )
            if result.get("success"):
                pipeline_state.add_log(f"Email ({account['email']}): {result['scanned']} scanned, {result['pii']} PII")
            else:
                pipeline_state.errors.append(f"Email ({account['email']}): {result.get('message', 'Failed')}")
                pipeline_state.add_log(f"Email ({account['email']}): FAILED — {result.get('message', '')}")

        pipeline_state.complete_stage("scanning_emails")

    # Stage 4: Scan cloud sources
    if sources.get("cloud", {}).get("enabled"):
        pipeline_state.update(current_stage="scanning_cloud")
        pipeline_state.add_log("Scanning cloud storage sources...")

        for provider_cfg in sources["cloud"].get("providers", []):
            result = _scan_cloud_source(
                cloud_cfg=provider_cfg,
                data_owner=data_owner,
                storage_root=storage_root,
                scan_store=scan_store,
                file_details=file_details,
                scan_activity=scan_activity,
            )
            source_results[f"cloud_{provider_cfg['provider']}"] = result
            total_files += result.get("scanned", 0)
            total_pii += result.get("pii", 0)
            processed += 1
            pipeline_state.update(
                sources_processed=processed,
                files_scanned=total_files,
                total_pii_detected=total_pii,
            )
            if result.get("success"):
                pipeline_state.add_log(f"Cloud ({provider_cfg['provider']}): {result['scanned']} scanned, {result['pii']} PII")
            else:
                pipeline_state.errors.append(f"Cloud ({provider_cfg['provider']}): {result.get('message', 'Failed')}")

        pipeline_state.complete_stage("scanning_cloud")

    # Stage 5: Scan folder sources
    if sources.get("folders"):
        pipeline_state.update(current_stage="scanning_folders")
        pipeline_state.add_log("Scanning enterprise folder sources...")

        for folder_cfg in sources["folders"]:
            if not folder_cfg.get("enabled"):
                continue
            result = _scan_folder_source(
                folder_cfg=folder_cfg,
                data_owner=data_owner,
                storage_root=storage_root,
                scan_store=scan_store,
                file_details=file_details,
                scan_activity=scan_activity,
            )
            source_results[f"folder_{folder_cfg['path']}"] = result
            total_files += result.get("scanned", 0)
            total_pii += result.get("pii", 0)
            processed += 1
            pipeline_state.update(
                sources_processed=processed,
                files_scanned=total_files,
                total_pii_detected=total_pii,
            )
            if result.get("success"):
                pipeline_state.add_log(f"Folder ({folder_cfg['path']}): {result['scanned']} scanned, {result['pii']} PII")
            else:
                pipeline_state.errors.append(f"Folder ({folder_cfg['path']}): {result.get('message', 'Failed')}")

        pipeline_state.complete_stage("scanning_folders")

    # Stage 6: Scan database sources
    if sources.get("databases"):
        pipeline_state.update(current_stage="scanning_databases")
        pipeline_state.add_log("Scanning database sources...")

        for db_cfg in sources["databases"]:
            if not db_cfg.get("enabled"):
                continue
            result = _scan_database_source(
                db_cfg=db_cfg,
                data_owner=data_owner,
                storage_root=storage_root,
                scan_store=scan_store,
                file_details=file_details,
                scan_activity=scan_activity,
            )
            source_results[f"database_{db_cfg.get('db_name', '')}"] = result
            total_files += result.get("scanned", 0)
            total_pii += result.get("pii", 0)
            processed += 1
            pipeline_state.update(
                sources_processed=processed,
                files_scanned=total_files,
                total_pii_detected=total_pii,
            )
            if result.get("success"):
                pipeline_state.add_log(f"Database ({db_cfg.get('db_name', '')}): {result['scanned']} scanned, {result['pii']} PII")
            else:
                pipeline_state.errors.append(f"Database: {result.get('message', 'Failed')}")

        pipeline_state.complete_stage("scanning_databases")

    # Stages 7-10: PII detection, classification, segregation, lineage
    # These are handled inline during file processing but we complete the stages
    pipeline_state.complete_stage("pii_detection")
    pipeline_state.complete_stage("classification")
    pipeline_state.complete_stage("segregation")
    pipeline_state.complete_stage("lineage_tracking")

    # Build security summary from file_details
    for fd in file_details:
        level = fd.get("security_level", "INTERNAL")
        security_counts[level] = security_counts.get(level, 0) + 1

    # Complete
    pipeline_state.update(
        status="completed",
        current_stage="completed",
        files_scanned=total_files,
        total_pii_detected=total_pii,
        security_summary=security_counts,
        lineage_count=len(file_details),
        completed_at=_now(),
        message=f"Pipeline complete — {total_files} files scanned, {total_pii} PII items detected across {processed} source(s).",
    )
    pipeline_state.complete_stage("completed")
    pipeline_state.add_log(f"Pipeline completed successfully. {total_files} files, {total_pii} PII items.")

    return {
        "success": True,
        "total_files_scanned": total_files,
        "total_pii_detected": total_pii,
        "sources_processed": processed,
        "source_results": source_results,
        "security_summary": security_counts,
        "message": pipeline_state.message,
    }
