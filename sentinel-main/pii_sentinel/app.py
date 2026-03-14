"""
app.py — PII Sentinel: Enterprise-Wide Personal Data Discovery & Classification
           Problem Statement 3 · DPDPA-Aligned

Flask application that provides:
  • File upload & scan  — emails, files, documents, archives (19 formats)
  • Folder scan         — recursive on-premises directory scan
  • Database scan       — SQLite table-level PII discovery
  • Auto-discover       — automatically discovers data sources on local machine
  • Cloud storage scan  — AWS S3, Google Drive, Azure Blob, Dropbox
  • PII pipeline        — text extraction → regex detection → classification
  • Risk scoring        — structured, semi-structured & unstructured data
  • Ownership mapping   — maps data owner, storage location, source type
  • DPDPA reports       — compliance-ready CSV with section references
  • JSON API            — Chart.js dashboard & React frontend integration
"""

import os
import json
import time
import sqlite3
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeoutError
from datetime import datetime
from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    flash,
    jsonify,
    Response,
    stream_with_context,
)

from scanner.file_parser import parse_file
from scanner.pii_detector import detect_all_pii, count_pii, total_pii
from scanner.classifier import classify_all, assess_risk, risk_color, sensitivity_color
from scanner.cloud_scanner import scan_cloud
from scanner.access_control import (
    build_access_map, access_summary, check_access,
    LEVEL_META, LEVEL_ACCESS, ROLES, LEVELS,
    classify_pii_security, get_allowed_roles,
    calculate_file_security_level,
)
from scanner.imap_scanner import scan_imap_inbox
from scanner.imap_monitor import IMAPMonitor
from scanner.data_lineage import (
    create_lineage_record,
    get_lineage_record,
    get_all_lineage_records,
    log_access_attempt,
    get_unauthorized_attempts,
    get_all_access_logs,
    lineage_summary,
    record_file_movement,
    update_sharing_path,
    get_movement_history,
    clear_lineage,
)
from scanner.file_segregation import (
    segregate_scanned_file,
    classify_file_security_level as seg_classify_level,
    get_segregation_log,
    get_segregation_summary,
    ensure_storage_structure,
    get_files_in_level,
    clear_segregation_log,
)
from scanner.enterprise_scanner import (
    scan_enterprise_email,
    scan_enterprise_cloud,
    scan_enterprise_folder,
    run_enterprise_scan,
)
from scanner.config_parser import parse_config_file, classify_sources, build_pipeline_config
from scanner.auto_pipeline import run_automated_pipeline, pipeline_state
from scanner.data_inventory import (
    create_inventory_record,
    get_all_inventory_records,
    get_inventory_record,
    update_consent_status,
    inventory_summary,
    dpdpa_compliance_report,
    clear_inventory,
)
from scanner.db_store import get_all_records as db_get_all_records, get_records_by_type, get_expired_records
from scanner.file_movement_tracker import (
    init_tracker_db,
    EVENT_TYPES,
    ingest_file_observation,
    append_file_event,
    get_event_log,
    get_file_timeline,
    get_lineage_graph,
    get_breach_alerts,
    tracker_summary,
)
from reports.report_generator import (
    build_rows,
    rows_to_csv,
    build_summary,
    build_dpdpa_report_csv,
    infer_data_source,
    infer_storage_location,
)


# ──────────────────────────────────────────────
# Flask setup
# ──────────────────────────────────────────────
app = Flask(__name__)
app.secret_key = "pii-sentinel-secret-key-change-in-prod"

UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), "uploads")
ALLOWED_EXTENSIONS = {
    # Plain text
    "txt", "log", "md",
    # Tabular
    "csv", "xlsx", "xls", "ods",
    # Documents
    "pdf", "docx", "pptx", "rtf", "odt",
    # Structured data
    "json", "xml",
    # Web
    "html", "htm",
    # Email
    "eml", "msg",
    # Archives
    "zip", "tar", "gz", "tgz",
}
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Enterprise storage for file segregation
ENTERPRISE_STORAGE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "enterprise_storage")
ensure_storage_structure(ENTERPRISE_STORAGE)

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["MAX_CONTENT_LENGTH"] = 64 * 1024 * 1024  # 64 MB (archives can be larger)

# Initialize the append-only lineage event store on server startup.
init_tracker_db()


# ──────────────────────────────────────────────
# In-memory store (resets on server restart)
# ──────────────────────────────────────────────
scan_store: list = []          # flat report rows (for CSV export & tables)
file_details: list = []        # per-file detail objects for the dashboard
scan_activity: list = []       # scan activity log

# Global real-time IMAP monitor (one instance per server process)
imap_monitor = IMAPMonitor()


def allowed_file(filename: str) -> bool:
    """Check if the uploaded file has an allowed extension."""
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def _classification_from_pii_counts(pii_counts: dict) -> tuple[str, list]:
    pii_types = [k for k, v in (pii_counts or {}).items() if int(v) > 0]
    classification = ", ".join(sorted(set(pii_types))) if pii_types else "Unclassified"
    return classification, pii_types


def _track_file_event_from_scan(
    *,
    file_path: str,
    filename: str,
    event_type: str,
    user_name: str,
    system_source: str,
    location: str,
    pii_counts: dict,
    risk_level: str,
    metadata: dict | None = None,
) -> dict:
    classification, pii_types = _classification_from_pii_counts(pii_counts)
    return ingest_file_observation(
        file_path=file_path,
        filename=filename,
        event_type=event_type,
        user_name=user_name,
        system_source=system_source,
        location=location,
        classification=classification,
        risk_level=risk_level,
        pii_types=pii_types,
        metadata=metadata or {},
    )


# ──────────────────────────────────────────────
# Routes
# ──────────────────────────────────────────────

@app.route("/")
def index():
    """Render the main dashboard page."""
    summary = build_summary(scan_store)
    return render_template(
        "index.html",
        summary=summary,
        file_details=file_details,
        scan_store=scan_store,
        scan_activity=scan_activity,
        risk_color=risk_color,
        sensitivity_color=sensitivity_color,
    )


@app.route("/tracker-summary")
def tracker_summary_page():
    """Render the file movement tracker dashboard page."""
    return render_template("tracker_summary.html")


@app.route("/upload", methods=["POST"])
def upload():
    """Handle file upload, scan for PII, and redirect back to dashboard."""
    if "files" not in request.files:
        flash("No files selected.", "warning")
        return redirect(url_for("index"))

    files = request.files.getlist("files")

    if not files or all(f.filename == "" for f in files):
        flash("No files selected.", "warning")
        return redirect(url_for("index"))

    # Optional metadata from the form
    data_owner = request.form.get("data_owner", "").strip() or "Unassigned"
    storage_label = request.form.get("storage_location", "").strip()

    scanned_count = 0
    total_pii_found = 0

    for file in files:
        if file and file.filename and allowed_file(file.filename):
            filename = file.filename
            filepath = os.path.join(app.config["UPLOAD_FOLDER"], filename)
            file.save(filepath)

            # ── Pipeline: extract → detect → classify ──
            text = parse_file(filepath)
            pii_results = detect_all_pii(text)
            pii_counts = count_pii(pii_results)
            pii_total_count = total_pii(pii_results)
            classifications = classify_all(pii_results)
            risk_level, risk_reason = assess_risk(pii_results)

            # Infer data source type
            source_type = infer_data_source(filename)
            storage_loc = storage_label if storage_label else infer_storage_location(filename)

            # Build report rows
            scan_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            rows = build_rows(filename, pii_results, scan_time, data_owner)

            # Override storage location if user provided it
            if storage_label:
                for r in rows:
                    r["storage_location"] = storage_label

            scan_store.extend(rows)

            # File size for display
            file_size = os.path.getsize(filepath)
            file_size_str = f"{file_size / 1024:.1f} KB" if file_size < 1048576 else f"{file_size / 1048576:.1f} MB"

            # Store per-file detail for dashboard display
            file_details.append({
                "filename": filename,
                "data_source": source_type,
                "storage_location": storage_loc,
                "data_owner": data_owner,
                "file_size": file_size_str,
                "pii_results": pii_results,
                "pii_counts": pii_counts,
                "pii_total": pii_total_count,
                "classifications": classifications,
                "risk_level": risk_level,
                "risk_reason": risk_reason,
                "scan_time": scan_time,
            })

            # Log activity
            scan_activity.append({
                "time": scan_time,
                "filename": filename,
                "risk_level": risk_level,
                "pii_total": pii_total_count,
                "action": f"Scanned {filename} — {pii_total_count} PII items found ({risk_level} risk)",
            })

            _track_file_event_from_scan(
                file_path=filepath,
                filename=filename,
                event_type="CREATE",
                user_name=data_owner,
                system_source="upload_portal",
                location=storage_loc,
                pii_counts=pii_counts,
                risk_level=risk_level,
                metadata={"origin": "manual_upload"},
            )

            scanned_count += 1
            total_pii_found += pii_total_count
        else:
            if file and file.filename:
                flash(f"Skipped unsupported file: {file.filename}", "warning")

    if scanned_count > 0:
        flash(
            f"✅ Successfully scanned {scanned_count} file(s) — {total_pii_found} PII items detected.",
            "success",
        )
    else:
        flash("No valid files were uploaded.", "warning")

    return redirect(url_for("index"))


@app.route("/download-report")
def download_report():
    """Generate and return a CSV compliance report."""
    if not scan_store:
        flash("No scan data available. Upload files first.", "warning")
        return redirect(url_for("index"))

    csv_data = rows_to_csv(scan_store)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    return Response(
        csv_data,
        mimetype="text/csv",
        headers={
            "Content-Disposition": f"attachment; filename=pii_sentinel_report_{timestamp}.csv"
        },
    )


@app.route("/api/summary")
def api_summary():
    """Return summary stats as JSON (consumed by Chart.js on the frontend)."""
    summary = build_summary(scan_store)
    return jsonify(summary)


@app.route("/api/activity")
def api_activity():
    """Return recent scan activity as JSON."""
    return jsonify(scan_activity[-20:])  # last 20 entries


@app.route("/clear", methods=["POST"])
def clear():
    """Clear all scan data and uploaded files."""
    scan_store.clear()
    file_details.clear()
    scan_activity.clear()
    for f in os.listdir(UPLOAD_FOLDER):
        fpath = os.path.join(UPLOAD_FOLDER, f)
        if os.path.isfile(fpath):
            os.remove(fpath)
    flash("All data cleared.", "info")
    return redirect(url_for("index"))


@app.route("/api/results")
def api_results():
    """Return all scanned file details as JSON (consumed by React frontend)."""
    return jsonify({
        "files": file_details,
        "count": len(file_details),
    })


@app.route("/api/upload", methods=["POST"])
def api_upload():
    """
    Async file upload endpoint that returns JSON.
    Called by the React frontend — no page redirect.
    """
    if "files" not in request.files:
        return jsonify({"success": False, "message": "No files selected."}), 400

    files = request.files.getlist("files")

    if not files or all(f.filename == "" for f in files):
        return jsonify({"success": False, "message": "No files selected."}), 400

    data_owner    = request.form.get("data_owner", "").strip() or "Unassigned"
    storage_label = request.form.get("storage_location", "").strip()

    scanned_count   = 0
    total_pii_found = 0
    skipped         = []

    for file in files:
        if file and file.filename and allowed_file(file.filename):
            filename = file.filename
            filepath = os.path.join(app.config["UPLOAD_FOLDER"], filename)
            file.save(filepath)

            text           = parse_file(filepath)
            pii_results    = detect_all_pii(text)
            pii_counts     = count_pii(pii_results)
            pii_total_count = total_pii(pii_results)
            classifications = classify_all(pii_results)
            risk_level, risk_reason = assess_risk(pii_results)

            source_type = infer_data_source(filename)
            storage_loc = storage_label if storage_label else infer_storage_location(filename)

            scan_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            rows = build_rows(filename, pii_results, scan_time, data_owner)

            if storage_label:
                for r in rows:
                    r["storage_location"] = storage_label

            scan_store.extend(rows)

            file_size     = os.path.getsize(filepath)
            file_size_str = (
                f"{file_size / 1024:.1f} KB"
                if file_size < 1048576
                else f"{file_size / 1048576:.1f} MB"
            )

            file_details.append({
                "filename":         filename,
                "data_source":      source_type,
                "storage_location": storage_loc,
                "data_owner":       data_owner,
                "file_size":        file_size_str,
                "pii_results":      pii_results,
                "pii_counts":       pii_counts,
                "pii_total":        pii_total_count,
                "classifications":  classifications,
                "risk_level":       risk_level,
                "risk_reason":      risk_reason,
                "scan_time":        scan_time,
            })

            # ── File segregation & lineage tracking ──
            security_level, dest_path, seg_msg = segregate_scanned_file(
                source_path=filepath, file_name=filename,
                pii_counts=pii_counts, storage_root=ENTERPRISE_STORAGE,
            )
            pii_types_detected = [pt for pt, c in pii_counts.items() if c > 0]
            authorized_roles = LEVEL_ACCESS.get(security_level, [])
            create_lineage_record(
                file_name=filename, origin_source="File Upload",
                original_path=filepath, current_path=dest_path,
                detected_pii=pii_types_detected,
                security_level=security_level,
                authorized_roles=authorized_roles,
            )
            file_details[-1]["security_level"] = security_level
            file_details[-1]["authorized_roles"] = authorized_roles

            scan_activity.append({
                "time":      scan_time,
                "filename":  filename,
                "risk_level": risk_level,
                "pii_total": pii_total_count,
                "action":    f"Scanned {filename} — {pii_total_count} PII items found ({risk_level} risk)",
            })

            _track_file_event_from_scan(
                file_path=filepath,
                filename=filename,
                event_type="CREATE",
                user_name=data_owner,
                system_source="upload_api",
                location=storage_loc,
                pii_counts=pii_counts,
                risk_level=risk_level,
                metadata={"origin": "api_upload", "security_level": security_level},
            )

            scanned_count   += 1
            total_pii_found += pii_total_count
        else:
            if file and file.filename:
                skipped.append(file.filename)

    if scanned_count == 0:
        return jsonify({"success": False, "message": "No valid files were uploaded."}), 400

    return jsonify({
        "success":   True,
        "scanned":   scanned_count,
        "total_pii": total_pii_found,
        "skipped":   skipped,
        "message":   f"Scanned {scanned_count} file(s) — {total_pii_found} PII items detected.",
    })


@app.route("/api/clear-data", methods=["POST"])
def api_clear_data():
    """Clear all scan data — JSON response for React frontend."""
    scan_store.clear()
    file_details.clear()
    scan_activity.clear()
    for f in os.listdir(UPLOAD_FOLDER):
        fpath = os.path.join(UPLOAD_FOLDER, f)
        if os.path.isfile(fpath):
            os.remove(fpath)
    return jsonify({"success": True, "message": "All data cleared."})


@app.route("/api/scan-folder", methods=["POST"])
def api_scan_folder():
    """
    Scan a local folder for all supported files and run the PII pipeline.
    Accepts JSON body: { folder_path, recursive, data_owner, max_files }
    """
    data         = request.get_json(silent=True) or {}
    folder_path  = data.get("folder_path", "").strip()
    recursive    = data.get("recursive", True)
    data_owner   = data.get("data_owner", "Unassigned").strip() or "Unassigned"
    max_files    = int(data.get("max_files", 100))

    if not folder_path:
        return jsonify({"success": False, "message": "No folder path provided."}), 400
    if not os.path.isdir(folder_path):
        return jsonify({"success": False, "message": f"Folder not found: {folder_path}"}), 400

    # Directories to skip (hidden, system, cache, build folders)
    SKIP_DIRS = {
        '.git', '.svn', '.hg', 'node_modules', '__pycache__', '.cache',
        '.vscode', '.idea', 'venv', '.env', 'AppData', 'Application Data',
        'Local Settings', 'Temporary Internet Files', '.npm', '.yarn',
        '.next', 'dist', 'build', '.tox', '.mypy_cache', '.pytest_cache',
    }

    # Collect files (with directory filtering + early stop)
    all_files = []
    limit_reached = False
    if recursive:
        for root, dirs, files in os.walk(folder_path):
            dirs[:] = [d for d in dirs if not d.startswith('.') and d not in SKIP_DIRS]
            for f in files:
                if f.startswith('.'):
                    continue
                all_files.append(os.path.join(root, f))
                if len(all_files) >= max_files * 3:
                    limit_reached = True
                    break
            if limit_reached:
                break
    else:
        try:
            for f in os.listdir(folder_path):
                fp = os.path.join(folder_path, f)
                if os.path.isfile(fp) and not f.startswith('.'):
                    all_files.append(fp)
        except PermissionError:
            return jsonify({"success": False, "message": f"Permission denied: {folder_path}"}), 403

    supported   = [fp for fp in all_files if fp.rsplit(".", 1)[-1].lower() in ALLOWED_EXTENSIONS]
    unsupported = len(all_files) - len(supported)

    # Cap to max_files
    if len(supported) > max_files:
        supported = supported[:max_files]
        limit_reached = True

    scanned_count   = 0
    total_pii_found = 0
    errors          = []
    skipped_large   = 0
    skipped_timeout = 0
    storage_loc     = f"Local Folder: {folder_path}"
    MAX_FILE_SIZE   = 1 * 1024 * 1024   # Skip files > 1 MB
    PER_FILE_TIMEOUT = 10               # seconds per file

    def _process_one(filepath):
        """Parse + detect PII for a single file."""
        fsize    = os.path.getsize(filepath)
        filename = os.path.basename(filepath)

        text = parse_file(filepath)
        if len(text) > 200_000:
            text = text[:200_000]

        pii_results     = detect_all_pii(text)
        pii_counts      = count_pii(pii_results)
        pii_total_count = total_pii(pii_results)
        classifications = classify_all(pii_results)
        risk_level, risk_reason = assess_risk(pii_results)
        source_type = infer_data_source(filename)
        scan_time   = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        rows = build_rows(filename, pii_results, scan_time, data_owner)
        for r in rows:
            r["storage_location"] = storage_loc

        fsize_str = f"{fsize/1024:.1f} KB" if fsize < 1_048_576 else f"{fsize/1_048_576:.1f} MB"

        return {
            "rows":     rows,
            "detail":   {
                "filename":         filename,
                "data_source":      source_type,
                "storage_location": storage_loc,
                "data_owner":       data_owner,
                "file_size":        fsize_str,
                "pii_results":      pii_results,
                "pii_counts":       pii_counts,
                "pii_total":        pii_total_count,
                "classifications":  classifications,
                "risk_level":       risk_level,
                "risk_reason":      risk_reason,
                "scan_time":        scan_time,
            },
            "activity": {
                "time":       scan_time,
                "filename":   filename,
                "risk_level": risk_level,
                "pii_total":  pii_total_count,
                "action":     f"Folder scan: {filename} — {pii_total_count} PII items ({risk_level} risk)",
            },
            "pii_total_count": pii_total_count,
        }

    # Filter out oversized files
    eligible = []
    for filepath in supported:
        try:
            if os.path.getsize(filepath) > MAX_FILE_SIZE:
                skipped_large += 1
            else:
                eligible.append(filepath)
        except OSError:
            errors.append({"file": filepath, "error": "Cannot read file"})

    # Process files in parallel with per-file timeout
    with ThreadPoolExecutor(max_workers=min(4, len(eligible) or 1)) as pool:
        futures = {pool.submit(_process_one, fp): fp for fp in eligible}
        for future in futures:
            filepath = futures[future]
            try:
                result = future.result(timeout=PER_FILE_TIMEOUT)
                if result:
                    scan_store.extend(result["rows"])
                    file_details.append(result["detail"])
                    scan_activity.append(result["activity"])
                    scanned_count   += 1
                    total_pii_found += result["pii_total_count"]
            except FuturesTimeoutError:
                skipped_timeout += 1
                future.cancel()
            except Exception as exc:
                errors.append({"file": filepath, "error": str(exc)})

    limit_note = f" (capped at {max_files})" if limit_reached else ""
    skip_note = f", {skipped_large} large file(s) skipped" if skipped_large > 0 else ""
    timeout_note = f", {skipped_timeout} file(s) timed out" if skipped_timeout > 0 else ""
    return jsonify({
        "success":            True,
        "folder":             folder_path,
        "total_files_found":  len(all_files),
        "supported_files":    len(supported),
        "scanned":            scanned_count,
        "unsupported":        unsupported,
        "skipped_large":      skipped_large,
        "skipped_timeout":    skipped_timeout,
        "errors":             len(errors),
        "limit_reached":      limit_reached,
        "total_pii":          total_pii_found,
        "message":            (
            f"Scanned {scanned_count} file(s) in folder{limit_note} — "
            f"{total_pii_found} PII items detected{skip_note}{timeout_note}."
        ),
    })


@app.route("/api/scan-database", methods=["POST"])
def api_scan_database():
    """
    Connect to a SQLite database file, read each table (up to 5000 rows),
    convert to text and run the full PII pipeline on each table.
    Accepts JSON body: { db_path, data_owner, row_limit }
    """
    data       = request.get_json(silent=True) or {}
    db_path    = data.get("db_path", "").strip()
    data_owner = data.get("data_owner", "Unassigned").strip() or "Unassigned"
    row_limit  = int(data.get("row_limit", 5000))

    if not db_path:
        return jsonify({"success": False, "message": "No database path provided."}), 400
    if not os.path.isfile(db_path):
        return jsonify({"success": False, "message": f"Database file not found: {db_path}"}), 400

    try:
        conn   = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")
        tables = [row[0] for row in cursor.fetchall()]
    except Exception as exc:
        return jsonify({"success": False, "message": f"Cannot open database: {exc}"}), 400

    if not tables:
        conn.close()
        return jsonify({"success": False, "message": "No tables found in the database."}), 400

    db_name         = os.path.basename(db_path)
    storage_loc     = f"SQLite: {db_path}"
    scanned_tables  = []
    total_pii_found = 0
    table_results   = []
    errors          = []

    for table in tables:
        try:
            cursor.execute(f'SELECT * FROM "{table}" LIMIT {row_limit}')  # noqa: S608
            db_rows   = cursor.fetchall()
            col_names = [desc[0] for desc in cursor.description] if cursor.description else []
            row_count = len(db_rows)

            # Convert table contents to a single text blob for scanning
            text_lines = [" | ".join(col_names)]
            for row in db_rows:
                text_lines.append(" | ".join(str(v) for v in row if v is not None))
            text = "\n".join(text_lines)

            pii_results     = detect_all_pii(text)
            pii_counts      = count_pii(pii_results)
            pii_total_count = total_pii(pii_results)
            classifications = classify_all(pii_results)
            risk_level, risk_reason = assess_risk(pii_results)

            # Use "dbname::tablename" as the virtual filename
            virtual_name = f"{db_name}::{table}"
            scan_time    = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            rows         = build_rows(virtual_name, pii_results, scan_time, data_owner)
            for r in rows:
                r["storage_location"] = storage_loc
                r["data_source"]      = "SQLite Database"

            scan_store.extend(rows)

            file_details.append({
                "filename":         virtual_name,
                "data_source":      "SQLite Database",
                "storage_location": storage_loc,
                "data_owner":       data_owner,
                "file_size":        f"{row_count} rows",
                "pii_results":      pii_results,
                "pii_counts":       pii_counts,
                "pii_total":        pii_total_count,
                "classifications":  classifications,
                "risk_level":       risk_level,
                "risk_reason":      risk_reason,
                "scan_time":        scan_time,
            })

            scan_activity.append({
                "time":       scan_time,
                "filename":   virtual_name,
                "risk_level": risk_level,
                "pii_total":  pii_total_count,
                "action":     f"DB scan: {table} ({row_count} rows) — {pii_total_count} PII items ({risk_level} risk)",
            })

            scanned_tables.append(table)
            total_pii_found += pii_total_count
            table_results.append({
                "table":     table,
                "rows":      row_count,
                "pii_total": pii_total_count,
                "risk":      risk_level,
            })

        except Exception as exc:
            errors.append({"table": table, "error": str(exc)})

    conn.close()

    return jsonify({
        "success":        True,
        "database":       db_path,
        "tables_found":   len(tables),
        "tables_scanned": len(scanned_tables),
        "total_pii":      total_pii_found,
        "table_results":  table_results,
        "errors":         len(errors),
        "message":        f"Scanned {len(scanned_tables)} table(s) — {total_pii_found} PII items detected.",
    })


@app.route("/api/auto-discover", methods=["POST"])
def api_auto_discover():
    """
    Auto-discover data sources on the local machine by scanning common OS paths.

    Accepts optional JSON body:
        {
          "data_owner"   : "HR Dept",     # optional
          "custom_paths" : ["/some/path"] # optional extra paths to include
          "max_files"    : 50,            # optional, default: 50
          "recursive"    : false          # optional, default: false (shallow scan)
        }

    Discovers files in:
        - User's Documents, Downloads, Desktop, Pictures
        - Any extra custom_paths provided
    Runs the full PII pipeline on every supported file found.
    """
    data         = request.get_json(silent=True) or {}
    data_owner   = data.get("data_owner", "Auto-Discovered").strip() or "Auto-Discovered"
    custom_paths = data.get("custom_paths", [])
    max_files    = int(data.get("max_files", 20))  # Limit files to prevent timeout
    recursive    = data.get("recursive", False)    # Shallow scan by default

    # Directories to skip (hidden, system, cache folders)
    SKIP_DIRS = {
        '.git', '.svn', '.hg', 'node_modules', '__pycache__', '.cache',
        '.vscode', '.idea', 'venv', '.env', 'AppData', 'Application Data',
        'Local Settings', 'Temporary Internet Files', '.npm', '.yarn'
    }

    # ── Build the list of default discovery paths ──────────────────────────────
    home = os.path.expanduser("~")
    default_dirs = [
        os.path.join(home, "Documents"),
        os.path.join(home, "Downloads"),
        os.path.join(home, "Desktop"),
        os.path.join(home, "OneDrive", "Documents"),
        os.path.join(home, "OneDrive", "Desktop"),
    ]

    search_paths = [p for p in default_dirs if os.path.isdir(p)]
    for cp in custom_paths:
        cp = str(cp).strip()
        if cp and os.path.isdir(cp):
            search_paths.append(cp)

    if not search_paths:
        return jsonify({
            "success": False,
            "message": "No valid discovery paths found on this system.",
        }), 400

    # ── Walk all paths and collect supported files (with limit) ────────────────
    discovered = []
    seen = set()
    limit_reached = False

    for base in search_paths:
        if limit_reached:
            break

        if recursive:
            # Recursive scan with directory filtering
            for root, dirs, files in os.walk(base):
                # Skip hidden and system directories
                dirs[:] = [d for d in dirs if not d.startswith('.') and d not in SKIP_DIRS]

                for fname in files:
                    if len(discovered) >= max_files:
                        limit_reached = True
                        break
                    # Skip hidden files
                    if fname.startswith('.'):
                        continue
                    ext = fname.rsplit(".", 1)[-1].lower() if "." in fname else ""
                    if ext not in ALLOWED_EXTENSIONS:
                        continue
                    fp = os.path.join(root, fname)
                    if fp in seen:
                        continue
                    seen.add(fp)
                    discovered.append(fp)

                if limit_reached:
                    break
        else:
            # Shallow scan (only top-level files in each directory)
            try:
                for fname in os.listdir(base):
                    if len(discovered) >= max_files:
                        limit_reached = True
                        break
                    fp = os.path.join(base, fname)
                    if not os.path.isfile(fp):
                        continue
                    # Skip hidden files
                    if fname.startswith('.'):
                        continue
                    ext = fname.rsplit(".", 1)[-1].lower() if "." in fname else ""
                    if ext not in ALLOWED_EXTENSIONS:
                        continue
                    if fp in seen:
                        continue
                    seen.add(fp)
                    discovered.append(fp)
            except PermissionError:
                continue

    if not discovered:
        return jsonify({
            "success"        : True,
            "message"        : "Discovery complete — no supported files found in scanned paths.",
            "paths_scanned"  : search_paths,
            "files_found"    : 0,
            "files_scanned"  : 0,
            "total_pii"      : 0,
            "errors"         : 0,
        })

    # ── Run PII pipeline on each discovered file (parallel) ─────────────────────
    scanned_count   = 0
    total_pii_found = 0
    errors          = []
    skipped_large   = 0
    skipped_timeout = 0
    MAX_FILE_SIZE   = 1 * 1024 * 1024  # Skip files > 1MB (too slow to parse)
    PER_FILE_TIMEOUT = 10              # seconds per file

    def _process_one(filepath):
        """Parse + detect PII for a single file. Returns result dict or None."""
        fsize = os.path.getsize(filepath)
        filename    = os.path.basename(filepath)
        storage_loc = f"Local: {os.path.dirname(filepath)}"

        text            = parse_file(filepath)
        # Truncate extremely long text to keep regex fast
        if len(text) > 200_000:
            text = text[:200_000]
        pii_results     = detect_all_pii(text)
        pii_counts      = count_pii(pii_results)
        pii_total_count = total_pii(pii_results)
        classifications = classify_all(pii_results)
        risk_level, risk_reason = assess_risk(pii_results)
        source_type     = infer_data_source(filename)
        scan_time       = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        rows = build_rows(filename, pii_results, scan_time, data_owner)
        for r in rows:
            r["storage_location"] = storage_loc

        fsize_str = f"{fsize/1024:.1f} KB" if fsize < 1_048_576 else f"{fsize/1_048_576:.1f} MB"

        return {
            "rows":     rows,
            "detail":   {
                "filename":         filename,
                "data_source":      source_type,
                "storage_location": storage_loc,
                "data_owner":       data_owner,
                "file_size":        fsize_str,
                "pii_results":      pii_results,
                "pii_counts":       pii_counts,
                "pii_total":        pii_total_count,
                "classifications":  classifications,
                "risk_level":       risk_level,
                "risk_reason":      risk_reason,
                "scan_time":        scan_time,
            },
            "activity": {
                "time":       scan_time,
                "filename":   filename,
                "risk_level": risk_level,
                "pii_total":  pii_total_count,
                "action":     f"Auto-discover: {filename} — {pii_total_count} PII items ({risk_level} risk)",
            },
            "pii_total_count": pii_total_count,
        }

    # Filter out oversized files first
    eligible = []
    for filepath in discovered:
        try:
            fsize = os.path.getsize(filepath)
            if fsize > MAX_FILE_SIZE:
                skipped_large += 1
            else:
                eligible.append(filepath)
        except OSError:
            errors.append({"file": filepath, "error": "Cannot read file"})

    # Process files in parallel with per-file timeout
    with ThreadPoolExecutor(max_workers=min(4, len(eligible) or 1)) as pool:
        futures = {pool.submit(_process_one, fp): fp for fp in eligible}
        for future in futures:
            filepath = futures[future]
            try:
                result = future.result(timeout=PER_FILE_TIMEOUT)
                if result:
                    scan_store.extend(result["rows"])
                    file_details.append(result["detail"])
                    scan_activity.append(result["activity"])
                    scanned_count   += 1
                    total_pii_found += result["pii_total_count"]
            except FuturesTimeoutError:
                skipped_timeout += 1
                future.cancel()
            except Exception as exc:
                errors.append({"file": filepath, "error": str(exc)})

    limit_note = f" (limit: {max_files})" if limit_reached else ""
    skip_note = f", {skipped_large} large file(s) skipped" if skipped_large > 0 else ""
    timeout_note = f", {skipped_timeout} file(s) timed out" if skipped_timeout > 0 else ""
    return jsonify({
        "success"       : True,
        "paths_scanned" : search_paths,
        "files_found"   : len(discovered),
        "files_scanned" : scanned_count,
        "skipped_large" : skipped_large,
        "skipped_timeout": skipped_timeout,
        "total_pii"     : total_pii_found,
        "errors"        : len(errors),
        "limit_reached" : limit_reached,
        "max_files"     : max_files,
        "message"       : (
            f"Auto-discovery complete — scanned {scanned_count} file(s){limit_note} across "
            f"{len(search_paths)} path(s), {total_pii_found} PII items detected{skip_note}{timeout_note}."
        ),
    })


@app.route("/api/scan-cloud", methods=["POST"])
def api_scan_cloud():
    """
    Scan files from a cloud storage provider for PII.

    Accepts JSON body:
        {
          "provider"    : "s3" | "gdrive" | "azure" | "dropbox",
          "credentials" : { ... provider-specific key/value pairs ... },
          "data_owner"  : "HR Dept",   (optional)
          "max_files"   : 100          (optional, default 100)
        }

    Providers and required credential keys:
      s3       — aws_access_key, aws_secret_key, bucket_name, [aws_region, prefix]
      gdrive   — service_account_json, [folder_id]
      azure    — container_name + (connection_string OR account_name+account_key), [prefix]
      dropbox  — access_token, [folder_path]
    """
    import shutil

    data        = request.get_json(silent=True) or {}
    provider    = data.get("provider", "").strip().lower()
    credentials = data.get("credentials", {})
    data_owner  = data.get("data_owner", "Cloud-Scanned").strip() or "Cloud-Scanned"
    max_files   = int(data.get("max_files", 100))

    if not provider:
        return jsonify({"success": False, "message": "No cloud provider specified."}), 400

    # ── Download files from cloud ──────────────────────────────────────────────
    tmp_dir, cloud_files, error = scan_cloud(provider, credentials, max_files=max_files)

    if error:
        return jsonify({"success": False, "message": error}), 400

    if not cloud_files:
        return jsonify({
            "success"      : True,
            "message"      : f"Cloud scan complete — no supported files found in {provider}.",
            "provider"     : provider,
            "files_found"  : 0,
            "files_scanned": 0,
            "total_pii"    : 0,
            "errors"       : 0,
        })

    # ── Run PII pipeline on each downloaded file ───────────────────────────────
    scanned_count   = 0
    total_pii_found = 0
    errors          = []

    for cf in cloud_files:
        filepath  = cf["local"]
        cloud_url = cf["cloud"]
        filename  = os.path.basename(filepath)

        try:
            storage_loc = f"Cloud ({provider.upper()}): {cloud_url}"

            text            = parse_file(filepath)
            pii_results     = detect_all_pii(text)
            pii_counts      = count_pii(pii_results)
            pii_total_count = total_pii(pii_results)
            classifications = classify_all(pii_results)
            risk_level, risk_reason = assess_risk(pii_results)
            source_type     = infer_data_source(filename)
            scan_time       = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            rows = build_rows(filename, pii_results, scan_time, data_owner)
            for r in rows:
                r["storage_location"] = storage_loc
                r["data_source"]      = f"Cloud Storage ({provider.upper()})"

            scan_store.extend(rows)

            fsize     = os.path.getsize(filepath)
            fsize_str = f"{fsize/1024:.1f} KB" if fsize < 1_048_576 else f"{fsize/1_048_576:.1f} MB"

            file_details.append({
                "filename"        : filename,
                "data_source"     : f"Cloud Storage ({provider.upper()})",
                "storage_location": storage_loc,
                "data_owner"      : data_owner,
                "file_size"       : fsize_str,
                "pii_results"     : pii_results,
                "pii_counts"      : pii_counts,
                "pii_total"       : pii_total_count,
                "classifications" : classifications,
                "risk_level"      : risk_level,
                "risk_reason"     : risk_reason,
                "scan_time"       : scan_time,
            })

            scan_activity.append({
                "time"      : scan_time,
                "filename"  : filename,
                "risk_level": risk_level,
                "pii_total" : pii_total_count,
                "action"    : f"Cloud ({provider}): {filename} — {pii_total_count} PII items ({risk_level} risk)",
            })

            _track_file_event_from_scan(
                file_path=filepath,
                filename=filename,
                event_type="DOWNLOAD",
                user_name=data_owner,
                system_source=f"cloud_{provider}",
                location=storage_loc,
                pii_counts=pii_counts,
                risk_level=risk_level,
                metadata={
                    "origin": cloud_url,
                    "from_location": cloud_url,
                    "to_location": filepath,
                    "expected_systems": [f"cloud_{provider}", "upload_api", "upload_portal"],
                },
            )

            scanned_count   += 1
            total_pii_found += pii_total_count

        except Exception as exc:
            errors.append({"file": filepath, "error": str(exc)})

    # ── Clean up temp directory ────────────────────────────────────────────────
    if tmp_dir and os.path.isdir(tmp_dir):
        shutil.rmtree(tmp_dir, ignore_errors=True)

    return jsonify({
        "success"      : True,
        "provider"     : provider,
        "files_found"  : len(cloud_files),
        "files_scanned": scanned_count,
        "total_pii"    : total_pii_found,
        "errors"       : len(errors),
        "message"      : (
            f"Cloud scan ({provider.upper()}) complete — "
            f"{scanned_count} file(s) scanned, {total_pii_found} PII items detected."
        ),
    })


# ──────────────────────────────────────────────
# Real-Time IMAP Monitor endpoints
# ──────────────────────────────────────────────

@app.route("/api/realtime/start", methods=["POST"])
def api_realtime_start():
    """
    Start the real-time IMAP monitor for a mailbox.

    Request JSON:
        { email, password, imap_host, imap_port, folder, poll_interval }
    """
    if imap_monitor.active:
        return jsonify({"success": False, "message": "Monitor is already running."}), 400

    data = request.get_json() or {}
    email_address = data.get("email", "").strip()
    password      = data.get("password", "").strip()

    if not email_address or not password:
        return jsonify({"success": False, "message": "Email and password are required."}), 400

    imap_host     = data.get("imap_host",     "imap.gmail.com").strip()
    imap_port     = int(data.get("imap_port",     993))
    folder        = data.get("folder",        "INBOX").strip()
    poll_interval = max(5, min(int(data.get("poll_interval", 10)), 60))

    imap_monitor.start(
        email_address = email_address,
        password      = password,
        imap_host     = imap_host,
        imap_port     = imap_port,
        folder        = folder,
        poll_interval = poll_interval,
        stores        = {
            "scan_store":    scan_store,
            "file_details":  file_details,
            "scan_activity": scan_activity,
        },
    )
    return jsonify({
        "success": True,
        "message": f"Real-time monitor started — watching {folder} on {imap_host} every {poll_interval}s.",
    })


@app.route("/api/realtime/stop", methods=["POST"])
def api_realtime_stop():
    """Stop the real-time IMAP monitor."""
    imap_monitor.stop()
    return jsonify({"success": True, "message": "Monitor stop signal sent."})


@app.route("/api/realtime/status", methods=["GET"])
def api_realtime_status():
    """Return current monitor status, config, and scan stats."""
    return jsonify(imap_monitor.status())


@app.route("/api/realtime/stream")
def api_realtime_stream():
    """
    Server-Sent Events stream.

    The client connects with EventSource('/api/realtime/stream').
    Events arrive as JSON-encoded 'data:' lines:
        { type, ts, ...payload }

    Event types:
        connected  — monitor just authenticated and is watching
        new_email  — a new email was scanned (may or may not have PII)
        heartbeat  — no new mail found on this poll cycle
        info       — informational message
        error      — recoverable error
        stopped    — monitor was stopped
    """
    @stream_with_context
    def _generate():
        # Yield an initial ping so the browser doesn't see a blank response
        yield f"data: {json.dumps({'type': 'ping', 'ts': datetime.now().isoformat()})}\n\n"
        while True:
            events = imap_monitor.drain_events(max_events=20)
            for ev in events:
                yield f"data: {json.dumps(ev)}\n\n"
            if not events:
                # Send keep-alive comment every 2 s to prevent proxy timeout
                yield ": keepalive\n\n"
            time.sleep(2)

    return Response(
        _generate(),
        mimetype="text/event-stream",
        headers={
            "Cache-Control":   "no-cache",
            "X-Accel-Buffering":"no",       # disable nginx buffering
            "Connection":      "keep-alive",
        },
    )


# ──────────────────────────────────────────────
# IMAP Email Scanner endpoint
# ──────────────────────────────────────────────
@app.route("/api/scan-imap", methods=["POST"])
def api_scan_imap():
    """
    Scan an IMAP inbox for PII in email bodies and attachments.

    Request JSON:
        {
          "email":       "user@gmail.com",
          "password":    "app-password-here",   # Gmail App Password
          "imap_host":   "imap.gmail.com",       # optional, default: imap.gmail.com
          "imap_port":   993,                    # optional, default: 993
          "max_emails":  20,                     # optional, default: 20
          "folder":      "INBOX"                 # optional, default: INBOX
        }

    Response JSON:
        { success, scanned, pii_emails, clean_emails, message }
    """
    data = request.get_json() or {}

    email_address = data.get("email", "").strip()
    password      = data.get("password", "").strip()
    imap_host     = data.get("imap_host", "imap.gmail.com").strip()
    imap_port     = int(data.get("imap_port", 993))
    max_emails    = min(int(data.get("max_emails", 20)), 100)
    folder        = data.get("folder", "INBOX").strip()

    if not email_address or not password:
        return jsonify({"success": False, "message": "Email and password are required."}), 400

    try:
        results = scan_imap_inbox(
            email_address = email_address,
            password      = password,
            imap_host     = imap_host,
            imap_port     = imap_port,
            max_emails    = max_emails,
            folder        = folder,
        )
    except (ConnectionError, ValueError) as e:
        return jsonify({"success": False, "message": str(e)}), 400
    except Exception as e:
        return jsonify({"success": False, "message": f"Scan error: {e}"}), 500

    scanned_count   = 0
    total_pii_found = 0

    for r in results:
        pii_results     = r.get("pii_results", {})
        pii_counts      = r.get("pii_counts", {})
        pii_total_count = r.get("pii_total", 0)
        risk_level      = r.get("risk_level", "NONE")
        risk_reason     = r.get("risk_reason", "")
        classifications = r.get("classifications", {})
        filename        = r.get("filename", "Unknown Email")
        scan_time       = r.get("scan_time", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        storage_loc     = r.get("storage_location", f"IMAP: {imap_host}")
        from_addr       = r.get("from_addr", "unknown")

        # Add to in-memory stores
        rows = build_rows(filename, pii_results, scan_time, email_address)
        for row in rows:
            row["storage_location"] = storage_loc
        scan_store.extend(rows)

        file_details.append({
            "filename":         filename,
            "data_source":      "email",
            "storage_location": storage_loc,
            "data_owner":       email_address,
            "file_size":        "—",
            "pii_results":      pii_results,
            "pii_counts":       pii_counts,
            "pii_total":        pii_total_count,
            "classifications":  classifications,
            "risk_level":       risk_level,
            "risk_reason":      risk_reason,
            "scan_time":        scan_time,
            "email_from":       from_addr,
            "email_subject":    r.get("subject", ""),
            "email_snippet":    r.get("snippet", ""),
        })

        scan_activity.append({
            "time":       scan_time,
            "filename":   filename,
            "risk_level": risk_level,
            "pii_total":  pii_total_count,
            "action":     f"Email: {filename} — {pii_total_count} PII items found ({risk_level} risk)",
        })

        pii_types_detected = [pt for pt, cnt in pii_counts.items() if cnt > 0]
        for attachment in r.get("attachment_hashes", []):
            append_file_event(
                file_hash=attachment.get("file_hash", ""),
                filename=attachment.get("filename", filename),
                event_type="SHARE",
                user_name=from_addr,
                system_source="email_imap",
                location=storage_loc,
                classification=", ".join(pii_types_detected) if pii_types_detected else "Unclassified",
                risk_level=risk_level,
                pii_types=pii_types_detected,
                metadata={
                    "email_subject": r.get("subject", ""),
                    "sender": from_addr,
                    "recipient": email_address,
                    "external": False,
                },
            )

        scanned_count   += 1
        total_pii_found += pii_total_count

    pii_emails   = sum(1 for r in results if r.get("pii_total", 0) > 0)
    clean_emails = scanned_count - pii_emails

    return jsonify({
        "success":     True,
        "scanned":     scanned_count,
        "pii_emails":  pii_emails,
        "clean_emails":clean_emails,
        "total_pii":   total_pii_found,
        "message": (
            f"IMAP scan complete — {scanned_count} email(s) scanned, "
            f"{pii_emails} with PII, {total_pii_found} total PII items detected."
        ),
    })


# ──────────────────────────────────────────────
# Organization-Wide Auto Scan endpoint
# ──────────────────────────────────────────────
@app.route("/api/org-scan", methods=["POST"])
def api_org_scan():
    """
    Orchestrate a full organization-wide scan across multiple data sources
    in a single request. The user provides credentials and paths for all
    the sources they want scanned, and this endpoint calls each existing
    scanner sequentially, aggregating results.

    Request JSON:
        {
          "org_name":    "Acme Corp",
          "data_owner":  "IT Security Team",
          "sources": {
              "folder": {
                  "enabled": true,
                  "folder_path": "C:\\OrgData",
                  "recursive": true,
                  "max_files": 100
              },
              "database": {
                  "enabled": true,
                  "db_path": "C:\\data\\app.db",
                  "row_limit": 5000
              },
              "cloud": {
                  "enabled": true,
                  "provider": "s3",
                  "credentials": { ... },
                  "max_files": 100
              },
              "email": {
                  "enabled": true,
                  "email": "user@company.com",
                  "password": "app-password",
                  "imap_host": "imap.gmail.com",
                  "max_emails": 50,
                  "folder": "INBOX"
              },
              "auto_discover": {
                  "enabled": true,
                  "custom_paths": [],
                  "max_files": 50,
                  "recursive": false
              }
          }
        }

    Response JSON:
        {
          "success": true,
          "org_name": "Acme Corp",
          "scan_results": { ... per-source results ... },
          "totals": { "sources_scanned", "total_files", "total_pii", "total_errors" },
          "message": "..."
        }
    """
    import shutil

    payload      = request.get_json(silent=True) or {}
    org_name     = payload.get("org_name", "").strip() or "Organization"
    data_owner   = payload.get("data_owner", "").strip() or org_name
    sources      = payload.get("sources", {})

    if not sources:
        return jsonify({"success": False, "message": "No data sources configured."}), 400

    scan_results     = {}
    sources_scanned  = 0
    total_files_all  = 0
    total_pii_all    = 0
    total_errors_all = 0

    # ── Helper: same PII pipeline used by all scanners below ──────────────
    def _run_pii_pipeline(filepath, filename, storage_loc_str, source_label, owner):
        """Run file through PII pipeline and store results. Returns pii count."""
        text = parse_file(filepath)
        if len(text) > 200_000:
            text = text[:200_000]
        pii_results     = detect_all_pii(text)
        pii_counts      = count_pii(pii_results)
        pii_total_count = total_pii(pii_results)
        classifications = classify_all(pii_results)
        risk_level, risk_reason = assess_risk(pii_results)
        source_type     = infer_data_source(filename)
        scan_time       = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        rows = build_rows(filename, pii_results, scan_time, owner)
        for r in rows:
            r["storage_location"] = storage_loc_str
            r["data_source"]      = source_label

        scan_store.extend(rows)

        fsize = os.path.getsize(filepath) if os.path.isfile(filepath) else 0
        fsize_str = f"{fsize/1024:.1f} KB" if fsize < 1_048_576 else f"{fsize/1_048_576:.1f} MB"

        file_details.append({
            "filename":         filename,
            "data_source":      source_label,
            "storage_location": storage_loc_str,
            "data_owner":       owner,
            "file_size":        fsize_str,
            "pii_results":      pii_results,
            "pii_counts":       pii_counts,
            "pii_total":        pii_total_count,
            "classifications":  classifications,
            "risk_level":       risk_level,
            "risk_reason":      risk_reason,
            "scan_time":        scan_time,
        })

        scan_activity.append({
            "time":       scan_time,
            "filename":   filename,
            "risk_level": risk_level,
            "pii_total":  pii_total_count,
            "action":     f"Org scan ({org_name}): {filename} — {pii_total_count} PII items ({risk_level} risk)",
        })

        return pii_total_count

    SKIP_DIRS = {
        '.git', '.svn', '.hg', 'node_modules', '__pycache__', '.cache',
        '.vscode', '.idea', 'venv', '.env', 'AppData', 'Application Data',
        'Local Settings', 'Temporary Internet Files', '.npm', '.yarn',
        '.next', 'dist', 'build', '.tox', '.mypy_cache', '.pytest_cache',
    }
    MAX_FILE_SIZE    = 1 * 1024 * 1024   # 1 MB
    PER_FILE_TIMEOUT = 10

    # ═══════════════════════════════════════════════════
    # 1) AUTO-DISCOVER scan
    # ═══════════════════════════════════════════════════
    ad_cfg = sources.get("auto_discover", {})
    if ad_cfg.get("enabled"):
        try:
            home = os.path.expanduser("~")
            default_dirs = [
                os.path.join(home, "Documents"),
                os.path.join(home, "Downloads"),
                os.path.join(home, "Desktop"),
                os.path.join(home, "OneDrive", "Documents"),
            ]
            custom_paths = ad_cfg.get("custom_paths", [])
            max_files    = int(ad_cfg.get("max_files", 50))
            recursive    = ad_cfg.get("recursive", False)

            search_paths = [p for p in default_dirs if os.path.isdir(p)]
            for cp in custom_paths:
                cp = str(cp).strip()
                if cp and os.path.isdir(cp):
                    search_paths.append(cp)

            discovered = []
            seen = set()
            for base in search_paths:
                if len(discovered) >= max_files:
                    break
                if recursive:
                    for root, dirs, files in os.walk(base):
                        dirs[:] = [d for d in dirs if not d.startswith('.') and d not in SKIP_DIRS]
                        for fname in files:
                            if len(discovered) >= max_files:
                                break
                            if fname.startswith('.'):
                                continue
                            ext = fname.rsplit(".", 1)[-1].lower() if "." in fname else ""
                            if ext not in ALLOWED_EXTENSIONS:
                                continue
                            fp = os.path.join(root, fname)
                            if fp not in seen:
                                seen.add(fp)
                                discovered.append(fp)
                        if len(discovered) >= max_files:
                            break
                else:
                    try:
                        for fname in os.listdir(base):
                            if len(discovered) >= max_files:
                                break
                            fp = os.path.join(base, fname)
                            if not os.path.isfile(fp) or fname.startswith('.'):
                                continue
                            ext = fname.rsplit(".", 1)[-1].lower() if "." in fname else ""
                            if ext not in ALLOWED_EXTENSIONS:
                                continue
                            if fp not in seen:
                                seen.add(fp)
                                discovered.append(fp)
                    except PermissionError:
                        pass

            ad_scanned = 0
            ad_pii     = 0
            ad_errors  = 0
            eligible = [fp for fp in discovered if os.path.getsize(fp) <= MAX_FILE_SIZE]

            with ThreadPoolExecutor(max_workers=min(4, len(eligible) or 1)) as pool:
                def _ad_process(filepath):
                    return _run_pii_pipeline(
                        filepath, os.path.basename(filepath),
                        f"Local: {os.path.dirname(filepath)}", "Auto-Discovered", data_owner)
                futures = {pool.submit(_ad_process, fp): fp for fp in eligible}
                for future in futures:
                    try:
                        pii_count = future.result(timeout=PER_FILE_TIMEOUT)
                        ad_scanned += 1
                        ad_pii += pii_count
                    except Exception:
                        ad_errors += 1

            scan_results["auto_discover"] = {
                "success": True, "files_found": len(discovered),
                "files_scanned": ad_scanned, "total_pii": ad_pii, "errors": ad_errors,
            }
            sources_scanned  += 1
            total_files_all  += ad_scanned
            total_pii_all    += ad_pii
            total_errors_all += ad_errors
        except Exception as exc:
            scan_results["auto_discover"] = {"success": False, "message": str(exc)}

    # ═══════════════════════════════════════════════════
    # 2) FOLDER scan
    # ═══════════════════════════════════════════════════
    folder_cfg = sources.get("folder", {})
    if folder_cfg.get("enabled"):
        try:
            folder_path = folder_cfg.get("folder_path", "").strip()
            recursive   = folder_cfg.get("recursive", True)
            max_files   = int(folder_cfg.get("max_files", 100))

            if folder_path and os.path.isdir(folder_path):
                all_files = []
                if recursive:
                    for root, dirs, files in os.walk(folder_path):
                        dirs[:] = [d for d in dirs if not d.startswith('.') and d not in SKIP_DIRS]
                        for f in files:
                            if not f.startswith('.'):
                                all_files.append(os.path.join(root, f))
                                if len(all_files) >= max_files * 3:
                                    break
                        if len(all_files) >= max_files * 3:
                            break
                else:
                    try:
                        for f in os.listdir(folder_path):
                            fp = os.path.join(folder_path, f)
                            if os.path.isfile(fp) and not f.startswith('.'):
                                all_files.append(fp)
                    except PermissionError:
                        pass

                supported = [fp for fp in all_files if fp.rsplit(".", 1)[-1].lower() in ALLOWED_EXTENSIONS][:max_files]
                eligible  = [fp for fp in supported if os.path.getsize(fp) <= MAX_FILE_SIZE]
                storage_loc = f"Local Folder: {folder_path}"

                f_scanned = 0
                f_pii     = 0
                f_errors  = 0
                with ThreadPoolExecutor(max_workers=min(4, len(eligible) or 1)) as pool:
                    def _f_process(filepath):
                        return _run_pii_pipeline(
                            filepath, os.path.basename(filepath),
                            storage_loc, f"Folder Scan ({org_name})", data_owner)
                    futures = {pool.submit(_f_process, fp): fp for fp in eligible}
                    for future in futures:
                        try:
                            pii_count = future.result(timeout=PER_FILE_TIMEOUT)
                            f_scanned += 1
                            f_pii += pii_count
                        except Exception:
                            f_errors += 1

                scan_results["folder"] = {
                    "success": True, "files_found": len(supported),
                    "files_scanned": f_scanned, "total_pii": f_pii, "errors": f_errors,
                }
                sources_scanned  += 1
                total_files_all  += f_scanned
                total_pii_all    += f_pii
                total_errors_all += f_errors
            else:
                scan_results["folder"] = {"success": False, "message": f"Folder not found: {folder_path}"}
        except Exception as exc:
            scan_results["folder"] = {"success": False, "message": str(exc)}

    # ═══════════════════════════════════════════════════
    # 3) DATABASE scan
    # ═══════════════════════════════════════════════════
    db_cfg = sources.get("database", {})
    if db_cfg.get("enabled"):
        try:
            db_path   = db_cfg.get("db_path", "").strip()
            row_limit = int(db_cfg.get("row_limit", 5000))

            if db_path and os.path.isfile(db_path):
                conn   = sqlite3.connect(db_path)
                cursor = conn.cursor()
                cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")
                tables = [row[0] for row in cursor.fetchall()]
                db_name     = os.path.basename(db_path)
                storage_loc = f"SQLite: {db_path}"

                db_scanned = 0
                db_pii     = 0
                db_errors  = 0

                for table in tables:
                    try:
                        cursor.execute(f'SELECT * FROM "{table}" LIMIT {row_limit}')  # noqa: S608
                        db_rows   = cursor.fetchall()
                        col_names = [desc[0] for desc in cursor.description] if cursor.description else []
                        row_count = len(db_rows)

                        text_lines = [" | ".join(col_names)]
                        for row in db_rows:
                            text_lines.append(" | ".join(str(v) for v in row if v is not None))
                        text = "\n".join(text_lines)

                        pii_results     = detect_all_pii(text)
                        pii_counts      = count_pii(pii_results)
                        pii_total_count = total_pii(pii_results)
                        classifications = classify_all(pii_results)
                        risk_level, risk_reason = assess_risk(pii_results)

                        virtual_name = f"{db_name}::{table}"
                        scan_time    = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                        rows = build_rows(virtual_name, pii_results, scan_time, data_owner)
                        for r in rows:
                            r["storage_location"] = storage_loc
                            r["data_source"]      = "SQLite Database"
                        scan_store.extend(rows)

                        file_details.append({
                            "filename": virtual_name, "data_source": "SQLite Database",
                            "storage_location": storage_loc, "data_owner": data_owner,
                            "file_size": f"{row_count} rows", "pii_results": pii_results,
                            "pii_counts": pii_counts, "pii_total": pii_total_count,
                            "classifications": classifications, "risk_level": risk_level,
                            "risk_reason": risk_reason, "scan_time": scan_time,
                        })
                        scan_activity.append({
                            "time": scan_time, "filename": virtual_name, "risk_level": risk_level,
                            "pii_total": pii_total_count,
                            "action": f"Org scan ({org_name}) DB: {table} — {pii_total_count} PII ({risk_level})",
                        })
                        db_scanned += 1
                        db_pii     += pii_total_count
                    except Exception:
                        db_errors += 1

                conn.close()
                scan_results["database"] = {
                    "success": True, "tables_found": len(tables),
                    "tables_scanned": db_scanned, "total_pii": db_pii, "errors": db_errors,
                }
                sources_scanned  += 1
                total_files_all  += db_scanned
                total_pii_all    += db_pii
                total_errors_all += db_errors
            else:
                scan_results["database"] = {"success": False, "message": f"Database not found: {db_path}"}
        except Exception as exc:
            scan_results["database"] = {"success": False, "message": str(exc)}

    # ═══════════════════════════════════════════════════
    # 4) CLOUD STORAGE scan
    # ═══════════════════════════════════════════════════
    cloud_cfg = sources.get("cloud", {})
    if cloud_cfg.get("enabled"):
        try:
            provider    = cloud_cfg.get("provider", "").strip().lower()
            credentials = cloud_cfg.get("credentials", {})
            max_files   = int(cloud_cfg.get("max_files", 100))

            if provider and credentials:
                tmp_dir, cloud_files, error = scan_cloud(provider, credentials, max_files=max_files)

                if error:
                    scan_results["cloud"] = {"success": False, "message": error}
                else:
                    c_scanned = 0
                    c_pii     = 0
                    c_errors  = 0

                    for cf in (cloud_files or []):
                        try:
                            pii_count = _run_pii_pipeline(
                                cf["local"], os.path.basename(cf["local"]),
                                f"Cloud ({provider.upper()}): {cf['cloud']}",
                                f"Cloud Storage ({provider.upper()})", data_owner)
                            c_scanned += 1
                            c_pii     += pii_count
                        except Exception:
                            c_errors += 1

                    if tmp_dir and os.path.isdir(tmp_dir):
                        shutil.rmtree(tmp_dir, ignore_errors=True)

                    scan_results["cloud"] = {
                        "success": True, "provider": provider,
                        "files_found": len(cloud_files or []),
                        "files_scanned": c_scanned, "total_pii": c_pii, "errors": c_errors,
                    }
                    sources_scanned  += 1
                    total_files_all  += c_scanned
                    total_pii_all    += c_pii
                    total_errors_all += c_errors
            else:
                scan_results["cloud"] = {"success": False, "message": "Missing provider or credentials."}
        except Exception as exc:
            scan_results["cloud"] = {"success": False, "message": str(exc)}

    # ═══════════════════════════════════════════════════
    # 5) EMAIL (IMAP) scan
    # ═══════════════════════════════════════════════════
    email_cfg = sources.get("email", {})
    if email_cfg.get("enabled"):
        try:
            email_address = email_cfg.get("email", "").strip()
            password      = email_cfg.get("password", "").strip()
            imap_host     = email_cfg.get("imap_host", "imap.gmail.com").strip()
            imap_port     = int(email_cfg.get("imap_port", 993))
            max_emails    = min(int(email_cfg.get("max_emails", 50)), 100)
            email_folder  = email_cfg.get("folder", "INBOX").strip()

            if email_address and password:
                results = scan_imap_inbox(
                    email_address=email_address, password=password,
                    imap_host=imap_host, imap_port=imap_port,
                    max_emails=max_emails, folder=email_folder,
                )

                e_scanned = 0
                e_pii     = 0
                for r in results:
                    pii_results     = r.get("pii_results", {})
                    pii_counts      = r.get("pii_counts", {})
                    pii_total_count = r.get("pii_total", 0)
                    risk_level      = r.get("risk_level", "NONE")
                    risk_reason     = r.get("risk_reason", "")
                    classifications = r.get("classifications", {})
                    filename        = r.get("filename", "Unknown Email")
                    scan_time_e     = r.get("scan_time", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
                    storage_loc     = r.get("storage_location", f"IMAP: {imap_host}")

                    rows = build_rows(filename, pii_results, scan_time_e, email_address)
                    for row in rows:
                        row["storage_location"] = storage_loc
                    scan_store.extend(rows)

                    file_details.append({
                        "filename": filename, "data_source": "email",
                        "storage_location": storage_loc, "data_owner": email_address,
                        "file_size": "—", "pii_results": pii_results,
                        "pii_counts": pii_counts, "pii_total": pii_total_count,
                        "classifications": classifications, "risk_level": risk_level,
                        "risk_reason": risk_reason, "scan_time": scan_time_e,
                    })
                    scan_activity.append({
                        "time": scan_time_e, "filename": filename, "risk_level": risk_level,
                        "pii_total": pii_total_count,
                        "action": f"Org scan ({org_name}) Email: {filename} — {pii_total_count} PII ({risk_level})",
                    })
                    e_scanned += 1
                    e_pii     += pii_total_count

                scan_results["email"] = {
                    "success": True, "emails_scanned": e_scanned, "total_pii": e_pii,
                }
                sources_scanned  += 1
                total_files_all  += e_scanned
                total_pii_all    += e_pii
            else:
                scan_results["email"] = {"success": False, "message": "Email and password required."}
        except Exception as exc:
            scan_results["email"] = {"success": False, "message": str(exc)}

    if sources_scanned == 0:
        return jsonify({
            "success": False,
            "message": "No data sources were enabled or all sources failed.",
            "scan_results": scan_results,
        }), 400

    return jsonify({
        "success":      True,
        "org_name":     org_name,
        "scan_results": scan_results,
        "totals": {
            "sources_scanned": sources_scanned,
            "total_files":     total_files_all,
            "total_pii":       total_pii_all,
            "total_errors":    total_errors_all,
        },
        "message": (
            f"Organization scan for '{org_name}' complete — "
            f"{sources_scanned} source(s) scanned, {total_files_all} item(s) analyzed, "
            f"{total_pii_all} PII items detected."
        ),
    })


# ──────────────────────────────────────────────
# Role-Based Access Map endpoint
# ──────────────────────────────────────────────
@app.route("/api/access-map", methods=["GET"])
def api_access_map():
    """
    Returns role-based data accessibility map for all scanned files.

    Response JSON:
        {
          "access_map": [ {file_name, pii_type, pii_count,
                           security_level, allowed_roles, denied_roles,
                           source_type, storage_location, data_owner}, ... ],
          "summary":    { "by_level": {...}, "by_role": {...}, "total": N },
          "roles":      [...],
          "level_meta": {...},
          "level_access": {...}
        }
    """
    entries = build_access_map(file_details)
    summary = access_summary(entries)
    return jsonify({
        "access_map":   entries,
        "summary":      summary,
        "roles":        ROLES,
        "level_meta":   LEVEL_META,
        "level_access": LEVEL_ACCESS,
    })


# ──────────────────────────────────────────────
# Data Lineage API endpoints
# ──────────────────────────────────────────────

@app.route("/api/data-lineage", methods=["GET"])
def api_data_lineage():
    """
    Return data lineage records for all tracked files.

    Response JSON:
        {
          "lineage": [ { file_name, origin_source, original_path, current_path,
                         sharing_path, detected_pii, security_level,
                         authorized_roles, access_history, movement_history, ... } ],
          "summary": { total_tracked_files, by_security_level, by_origin_source,
                       total_movements, total_access_attempts, total_unauthorized,
                       recent_movements, recent_access },
          "count": N
        }
    """
    records = get_all_lineage_records()
    summary = lineage_summary()
    return jsonify({
        "lineage": records,
        "summary": summary,
        "count": len(records),
    })


@app.route("/api/data-lineage/<path:file_name>", methods=["GET"])
def api_data_lineage_file(file_name):
    """
    Return data lineage for a specific file.

    Response JSON:
        { file_name, origin_source, original_path, current_path,
          sharing_path, detected_pii, security_level,
          authorized_roles, access_history, movement_history }
    """
    record = get_lineage_record(file_name)
    if not record:
        return jsonify({"success": False, "message": f"No lineage record for: {file_name}"}), 404
    return jsonify({"success": True, "lineage": record})


# ──────────────────────────────────────────────
# File Movement Tracking API endpoints
# ──────────────────────────────────────────────

@app.route("/api/file-events", methods=["POST"])
def api_file_events_ingest():
    """
    Append a file lifecycle event to the central append-only event log.

    Request JSON:
        {
          "file_hash": "...",                # optional if file_path/content_base64 is sent
          "file_path": "C:/path/file.csv",   # optional
          "content_base64": "...",           # optional
          "filename": "employee.csv",
          "event_type": "CREATE|READ|COPY|MOVE|DOWNLOAD|SHARE|MODIFY|DELETE",
          "user": "employee1",
          "system_source": "laptop|gmail|drive|database|s3",
          "location": "C:/... or system uri",
          "classification": "Aadhaar",
          "risk_level": "HIGH",
          "pii_types": ["Aadhaar", "PAN"],
          "metadata": {"external": true, "from_location": "...", "to_location": "..."}
        }
    """
    payload = request.get_json(silent=True) or {}

    filename = str(payload.get("filename", "")).strip()
    event_type = str(payload.get("event_type", "")).strip().upper()
    user_name = str(payload.get("user", "unknown")).strip() or "unknown"
    system_source = str(payload.get("system_source", "unknown_system")).strip() or "unknown_system"
    location = str(payload.get("location", "unknown_location")).strip() or "unknown_location"

    if not filename or not event_type:
        return jsonify({"success": False, "message": "filename and event_type are required."}), 400
    if event_type not in EVENT_TYPES:
        return jsonify({"success": False, "message": f"Unsupported event_type: {event_type}"}), 400

    file_path = str(payload.get("file_path", "")).strip() or None
    file_hash = str(payload.get("file_hash", "")).strip() or None
    content_base64 = str(payload.get("content_base64", "")).strip() or None
    classification = str(payload.get("classification", "Unclassified")).strip() or "Unclassified"
    risk_level = str(payload.get("risk_level", "LOW")).strip() or "LOW"
    pii_types = payload.get("pii_types", [])
    metadata = payload.get("metadata", {}) or {}

    try:
        out = ingest_file_observation(
            file_path=file_path,
            content_base64=content_base64,
            file_hash=file_hash,
            filename=filename,
            event_type=event_type,
            user_name=user_name,
            system_source=system_source,
            location=location,
            classification=classification,
            risk_level=risk_level,
            pii_types=pii_types,
            metadata=metadata,
        )
        return jsonify(out)
    except Exception as exc:
        return jsonify({"success": False, "message": str(exc)}), 400


@app.route("/api/file-events", methods=["GET"])
def api_file_events_list():
    """Return append-only file movement events (newest first)."""
    file_hash = request.args.get("file_hash", "").strip() or None
    limit = int(request.args.get("limit", 200))
    events = get_event_log(file_hash=file_hash, limit=limit)
    return jsonify({"success": True, "count": len(events), "events": events})


@app.route("/api/file-events/email", methods=["POST"])
def api_file_events_email():
    """Email connector endpoint for attachment share/download lineage events."""
    payload = request.get_json(silent=True) or {}
    attachment_name = str(payload.get("filename", "attachment")).strip() or "attachment"
    sender = str(payload.get("sender", "unknown_sender")).strip() or "unknown_sender"
    recipient = str(payload.get("recipient", "unknown_recipient")).strip() or "unknown_recipient"
    event_type = str(payload.get("event_type", "SHARE")).strip().upper()
    system_source = str(payload.get("system_source", "gmail")).strip() or "gmail"
    location = str(payload.get("location", f"email://{system_source}")).strip()

    if event_type not in EVENT_TYPES:
        return jsonify({"success": False, "message": f"Unsupported event_type: {event_type}"}), 400

    metadata = payload.get("metadata", {}) or {}
    metadata.update({"sender": sender, "recipient": recipient, "connector": "email"})

    try:
        out = ingest_file_observation(
            file_path=payload.get("file_path"),
            content_base64=payload.get("content_base64"),
            file_hash=payload.get("file_hash"),
            filename=attachment_name,
            event_type=event_type,
            user_name=sender,
            system_source=system_source,
            location=location,
            classification=str(payload.get("classification", "Unclassified")),
            risk_level=str(payload.get("risk_level", "LOW")),
            pii_types=payload.get("pii_types", []),
            metadata=metadata,
        )
        return jsonify(out)
    except Exception as exc:
        return jsonify({"success": False, "message": str(exc)}), 400


@app.route("/api/file-events/cloud", methods=["POST"])
def api_file_events_cloud():
    """Cloud connector endpoint for upload/download/share/delete lineage events."""
    payload = request.get_json(silent=True) or {}
    provider = str(payload.get("provider", "cloud")).strip().lower() or "cloud"
    event_type = str(payload.get("event_type", "DOWNLOAD")).strip().upper()
    filename = str(payload.get("filename", "cloud_object")).strip() or "cloud_object"
    user_name = str(payload.get("user", "cloud_service")).strip() or "cloud_service"
    cloud_path = str(payload.get("cloud_path", "")).strip()
    local_path = str(payload.get("local_path", "")).strip()

    if event_type not in EVENT_TYPES:
        return jsonify({"success": False, "message": f"Unsupported event_type: {event_type}"}), 400

    metadata = payload.get("metadata", {}) or {}
    if cloud_path:
        metadata.setdefault("from_location", cloud_path)
    if local_path:
        metadata.setdefault("to_location", local_path)
    metadata.setdefault("connector", "cloud")

    try:
        out = ingest_file_observation(
            file_path=payload.get("file_path") or (local_path if os.path.isfile(local_path) else None),
            content_base64=payload.get("content_base64"),
            file_hash=payload.get("file_hash"),
            filename=filename,
            event_type=event_type,
            user_name=user_name,
            system_source=f"cloud_{provider}",
            location=cloud_path or local_path or f"cloud://{provider}",
            classification=str(payload.get("classification", "Unclassified")),
            risk_level=str(payload.get("risk_level", "LOW")),
            pii_types=payload.get("pii_types", []),
            metadata=metadata,
        )
        return jsonify(out)
    except Exception as exc:
        return jsonify({"success": False, "message": str(exc)}), 400


@app.route("/api/file-timeline/<file_hash>", methods=["GET"])
def api_file_timeline(file_hash):
    """Return chronological file lifecycle events for one fingerprint."""
    return jsonify(get_file_timeline(file_hash=file_hash))


@app.route("/api/file-lineage-graph", methods=["GET"])
def api_file_lineage_graph():
    """Return graph nodes/edges representing file movement lineage."""
    file_hash = request.args.get("file_hash", "").strip() or None
    graph = get_lineage_graph(file_hash=file_hash)
    return jsonify({"success": True, **graph})


@app.route("/api/file-alerts", methods=["GET"])
def api_file_alerts():
    """Return breach alerts generated by event rules."""
    limit = int(request.args.get("limit", 100))
    alerts = get_breach_alerts(limit=limit)
    return jsonify({"success": True, "count": len(alerts), "alerts": alerts})


@app.route("/api/file-tracker-summary", methods=["GET"])
def api_file_tracker_summary():
    """Return aggregate metrics for the file event tracker subsystem."""
    return jsonify({"success": True, "summary": tracker_summary()})


@app.route("/api/check-access", methods=["POST"])
def api_check_access():
    """
    Check if a user role has access to a security level.

    Request JSON:
        {
          "user_role": "Employee",
          "security_level": "CONFIDENTIAL",
          "user": "employee_15",        (optional, for logging)
          "file_name": "report.xlsx"    (optional, for logging)
        }

    Response JSON:
        {
          "user_role": "Employee",
          "security_level": "CONFIDENTIAL",
          "authorized": false,
          "message": "ACCESS DENIED",
          "reason": "Employee does not have clearance for CONFIDENTIAL data"
        }
    """
    data = request.get_json(silent=True) or {}
    user_role = data.get("user_role", "").strip()
    security_level = data.get("security_level", "").strip()
    user = data.get("user", "anonymous").strip()
    file_name = data.get("file_name", "").strip()

    if not user_role or not security_level:
        return jsonify({
            "success": False,
            "message": "user_role and security_level are required.",
        }), 400

    result = check_access(user_role, security_level)

    # Log the access attempt if a file_name is provided
    if file_name:
        status = "AUTHORIZED" if result["authorized"] else "DENIED"
        log_access_attempt(
            file_name=file_name,
            user=user,
            role=user_role,
            status=status,
            details=result["reason"],
        )

    return jsonify(result)


@app.route("/api/access-logs", methods=["GET"])
def api_access_logs():
    """
    Return all access attempt logs.

    Response JSON:
        {
          "logs": [ { file_name, user, role, status, timestamp, details } ],
          "total": N,
          "unauthorized": N
        }
    """
    logs = get_all_access_logs()
    unauthorized = get_unauthorized_attempts()
    return jsonify({
        "logs": logs,
        "total": len(logs),
        "unauthorized": len(unauthorized),
        "unauthorized_attempts": unauthorized,
    })


@app.route("/api/segregation-status", methods=["GET"])
def api_segregation_status():
    """
    Return file segregation status and summary.

    Response JSON:
        {
          "summary": { total_segregated, by_level, recent },
          "files_by_level": { "PUBLIC": [...], "INTERNAL": [...], ... },
          "log": [...]
        }
    """
    summary = get_segregation_summary()
    files_by_level = {}
    for level in ["PUBLIC", "INTERNAL", "RESTRICTED", "CONFIDENTIAL"]:
        files_by_level[level] = get_files_in_level(level, ENTERPRISE_STORAGE)

    return jsonify({
        "summary": summary,
        "files_by_level": files_by_level,
        "log": get_segregation_log(),
    })


@app.route("/api/enterprise-scan", methods=["POST"])
def api_enterprise_scan():
    """
    Run a full enterprise data source scan.

    Request JSON:
        {
          "data_owner": "IT Security Team",
          "sources": {
            "email": {
              "enabled": true,
              "email": "user@company.com",
              "password": "app-password",
              "imap_host": "imap.gmail.com",
              "max_emails": 50
            },
            "cloud": {
              "enabled": true,
              "provider": "s3",
              "credentials": { ... },
              "max_files": 100
            },
            "folders": [
              {
                "enabled": true,
                "path": "/data/shared",
                "recursive": true,
                "max_files": 100
              }
            ]
          }
        }

    Response JSON:
        {
          "success": true,
          "total_files_scanned": N,
          "total_pii_detected": N,
          "results": { email: {...}, cloud: {...}, folders: [...] },
          "message": "..."
        }
    """
    data = request.get_json(silent=True) or {}
    data_owner = data.get("data_owner", "Enterprise").strip() or "Enterprise"
    sources = data.get("sources", {})

    if not sources:
        return jsonify({"success": False, "message": "No data sources configured."}), 400

    result = run_enterprise_scan(
        sources=sources,
        data_owner=data_owner,
        storage_root=ENTERPRISE_STORAGE,
    )

    # Integrate results into the in-memory stores
    all_sub_results = []

    # Collect from email
    if result["results"].get("email") and result["results"]["email"].get("results"):
        all_sub_results.extend(result["results"]["email"]["results"])

    # Collect from cloud
    if result["results"].get("cloud") and result["results"]["cloud"].get("results"):
        all_sub_results.extend(result["results"]["cloud"]["results"])

    # Collect from folders
    for folder_result in result["results"].get("folders", []):
        if folder_result.get("results"):
            all_sub_results.extend(folder_result["results"])

    # Add all results to in-memory stores
    for sr in all_sub_results:
        if sr.get("rows"):
            scan_store.extend(sr["rows"])
        if sr.get("detail"):
            file_details.append(sr["detail"])
        if sr.get("activity"):
            scan_activity.append(sr["activity"])

    return jsonify(result)


# ──────────────────────────────────────────────
# Clear data — updated to also clear lineage and segregation logs
# ──────────────────────────────────────────────

@app.route("/api/clear-all", methods=["POST"])
def api_clear_all():
    """Clear all scan data, lineage, and segregation logs."""
    scan_store.clear()
    file_details.clear()
    scan_activity.clear()
    clear_lineage()
    clear_segregation_log()
    clear_inventory()
    pipeline_state.reset()
    for f in os.listdir(UPLOAD_FOLDER):
        fpath = os.path.join(UPLOAD_FOLDER, f)
        if os.path.isfile(fpath):
            os.remove(fpath)
    return jsonify({"success": True, "message": "All data cleared including lineage and segregation logs."})


# ──────────────────────────────────────────────
# Download report endpoint (kept as-is)
# ──────────────────────────────────────────────

@app.route("/api/download-report")
def api_download_report():
    """Generate and return a CSV compliance report."""
    if not scan_store:
        return jsonify({"success": False, "message": "No scan data available."}), 400
    csv_data = rows_to_csv(scan_store)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    return Response(
        csv_data,
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment; filename=pii_sentinel_report_{timestamp}.csv"},
    )


# ──────────────────────────────────────────────
# History endpoint
# ──────────────────────────────────────────────

@app.route("/api/history")
def api_history():
    """Return scan history with file details."""
    return jsonify({
        "file_details": file_details,
        "scan_activity": scan_activity,
        "count": len(file_details),
    })


# ──────────────────────────────────────────────
# Automated Config-Based Pipeline Endpoints
# ──────────────────────────────────────────────

@app.route("/api/upload-config", methods=["POST"])
def api_upload_config():
    """
    Upload a single enterprise scan configuration file (CSV, XLSX, or PDF)
    and automatically trigger the full scanning pipeline.

    The configuration file defines all data source credentials and targets.
    Once uploaded, the system:
        1. Parses the config file
        2. Identifies all data sources
        3. Connects to each service
        4. Scans all discovered files
        5. Runs PII detection
        6. Classifies sensitivity levels
        7. Segregates files by classification
        8. Tracks lineage records
        9. Builds personal data inventory

    Request: multipart/form-data with field 'config' (file) and optional 'data_owner'
    Response: Pipeline results JSON
    """
    import threading as _threading

    if "config" not in request.files:
        return jsonify({"success": False, "message": "No configuration file uploaded."}), 400

    config_file = request.files["config"]
    if not config_file or not config_file.filename:
        return jsonify({"success": False, "message": "No file selected."}), 400

    filename = config_file.filename
    ext = os.path.splitext(filename)[1].lower()
    if ext not in (".csv", ".xlsx", ".pdf"):
        return jsonify({
            "success": False,
            "message": f"Unsupported config format: {ext}. Use CSV, XLSX, or PDF.",
        }), 400

    data_owner = request.form.get("data_owner", "").strip() or "Enterprise Security Team"

    # Save config file
    filepath = os.path.join(app.config["UPLOAD_FOLDER"], f"config_{filename}")
    config_file.save(filepath)

    # Stage 1: Parse config file
    try:
        sources = parse_config_file(filepath)
    except Exception as e:
        return jsonify({"success": False, "message": f"Config parse error: {e}"}), 400

    if not sources:
        return jsonify({"success": False, "message": "No valid data sources found in configuration file."}), 400

    # Stage 2: Classify and build pipeline config
    classified = classify_sources(sources)
    pipeline_config = build_pipeline_config(sources)

    # Stage 3: Run automated pipeline in background thread
    def _run_pipeline():
        run_automated_pipeline(
            pipeline_config=pipeline_config,
            data_owner=data_owner,
            storage_root=ENTERPRISE_STORAGE,
            scan_store=scan_store,
            file_details=file_details,
            scan_activity=scan_activity,
        )
        # Build inventory records for all scanned files
        for fd in file_details:
            pii_types = [pt for pt, c in fd.get("pii_counts", {}).items() if c > 0]
            if fd["filename"] not in {r["file_name"] for r in get_all_inventory_records()}:
                create_inventory_record(
                    file_name=fd["filename"],
                    detected_pii_types=pii_types,
                    data_owner=fd.get("data_owner", data_owner),
                    storage_location=fd.get("storage_location", ""),
                    security_level=fd.get("security_level", "INTERNAL"),
                    data_source=fd.get("data_source", "unknown"),
                    pii_counts=fd.get("pii_counts", {}),
                )

    pipeline_thread = _threading.Thread(target=_run_pipeline, daemon=True)
    pipeline_thread.start()

    # Return immediately with source detection results
    source_counts = {k: len(v) for k, v in classified.items() if v}
    return jsonify({
        "success": True,
        "config_file": filename,
        "sources_detected": source_counts,
        "total_sources": sum(source_counts.values()),
        "raw_entries": len(sources),
        "pipeline_status": "running",
        "message": (
            f"Configuration parsed — {sum(source_counts.values())} data source(s) "
            f"detected. Pipeline started automatically."
        ),
    })


@app.route("/api/scan-status", methods=["GET"])
def api_scan_status():
    """
    Return the current automated pipeline execution status.

    Polled by the frontend to show real-time progress.

    Response JSON:
        {
          "status": "idle" | "running" | "completed" | "failed",
          "current_stage": "...",
          "stages_completed": [...],
          "sources_detected": {...},
          "files_scanned": N,
          "total_pii_detected": N,
          "security_summary": {...},
          "progress_log": [...]
        }
    """
    return jsonify(pipeline_state.to_dict())


@app.route("/api/security-summary", methods=["GET"])
def api_security_summary():
    """
    Return security classification summary across all scanned files.

    Response JSON:
        {
          "by_level": {"PUBLIC": N, "INTERNAL": N, ...},
          "total_files": N,
          "files_with_pii": N,
          "pii_type_counts": {...}
        }
    """
    by_level = {}
    pii_type_counts = {}
    files_with_pii = 0

    for fd in file_details:
        level = fd.get("security_level", "INTERNAL")
        by_level[level] = by_level.get(level, 0) + 1

        pii_counts = fd.get("pii_counts", {})
        has_pii = False
        for pt, count in pii_counts.items():
            if count > 0:
                has_pii = True
                pii_type_counts[pt] = pii_type_counts.get(pt, 0) + count
        if has_pii:
            files_with_pii += 1

    return jsonify({
        "by_level": by_level,
        "total_files": len(file_details),
        "files_with_pii": files_with_pii,
        "pii_type_counts": pii_type_counts,
    })


# ──────────────────────────────────────────────
# DPDPA Compliance Endpoints
# ──────────────────────────────────────────────

@app.route("/api/data-inventory", methods=["GET"])
def api_data_inventory():
    """
    Return the DPDPA personal data inventory catalog.

    Response JSON:
        {
          "inventory": [...],
          "summary": {...},
          "count": N
        }
    """
    records = get_all_inventory_records()
    summary = inventory_summary()
    return jsonify({
        "inventory": records,
        "summary": summary,
        "count": len(records),
    })


@app.route("/api/data-inventory/<path:file_name>", methods=["GET"])
def api_data_inventory_file(file_name):
    """Return inventory record for a specific file."""
    record = get_inventory_record(file_name)
    if not record:
        return jsonify({"success": False, "message": f"No inventory record for: {file_name}"}), 404
    return jsonify({"success": True, "record": record})


@app.route("/api/data-inventory/update-consent", methods=["POST"])
def api_update_consent():
    """
    Update consent status for a file in the data inventory.

    Request JSON:
        {
          "file_name": "employee_records.xlsx",
          "consent_status": "verified"
        }
    """
    data = request.get_json(silent=True) or {}
    file_name = data.get("file_name", "").strip()
    consent_status = data.get("consent_status", "").strip()

    if not file_name or not consent_status:
        return jsonify({"success": False, "message": "file_name and consent_status required."}), 400

    valid = ("verified", "pending", "requires_verification", "notice_based", "not_applicable")
    if consent_status not in valid:
        return jsonify({"success": False, "message": f"Invalid consent_status. Use: {', '.join(valid)}"}), 400

    if update_consent_status(file_name, consent_status):
        return jsonify({"success": True, "message": f"Consent status updated to '{consent_status}' for {file_name}."})
    return jsonify({"success": False, "message": f"File not found in inventory: {file_name}"}), 404


@app.route("/api/dpdpa-report", methods=["GET"])
def api_dpdpa_report():
    """
    Return the DPDPA compliance assessment report as JSON.

    Response JSON:
        {
          "report_title": "...",
          "generated_at": "...",
          "summary": {...},
          "applicable_obligations": [...],
          "consent_gaps": [...],
          "high_risk_files": [...],
          "recommendations": [...]
        }
    """
    # Auto-populate inventory from file_details if empty
    existing = {r["file_name"] for r in get_all_inventory_records()}
    for fd in file_details:
        if fd["filename"] not in existing:
            pii_types = [pt for pt, c in fd.get("pii_counts", {}).items() if c > 0]
            create_inventory_record(
                file_name=fd["filename"],
                detected_pii_types=pii_types,
                data_owner=fd.get("data_owner", "Unassigned"),
                storage_location=fd.get("storage_location", ""),
                security_level=fd.get("security_level", "INTERNAL"),
                data_source=fd.get("data_source", "unknown"),
                pii_counts=fd.get("pii_counts", {}),
            )
            existing.add(fd["filename"])

    report = dpdpa_compliance_report()
    return jsonify(report)


@app.route("/api/dpdpa-report/csv")
def api_dpdpa_report_csv():
    """Download DPDPA compliance report as CSV."""
    # Auto-populate inventory
    existing = {r["file_name"] for r in get_all_inventory_records()}
    for fd in file_details:
        if fd["filename"] not in existing:
            pii_types = [pt for pt, c in fd.get("pii_counts", {}).items() if c > 0]
            create_inventory_record(
                file_name=fd["filename"],
                detected_pii_types=pii_types,
                data_owner=fd.get("data_owner", "Unassigned"),
                storage_location=fd.get("storage_location", ""),
                security_level=fd.get("security_level", "INTERNAL"),
                data_source=fd.get("data_source", "unknown"),
                pii_counts=fd.get("pii_counts", {}),
            )
            existing.add(fd["filename"])

    records = get_all_inventory_records()
    if not records:
        return jsonify({"success": False, "message": "No data in inventory."}), 400

    csv_data = build_dpdpa_report_csv(records)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    return Response(
        csv_data,
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment; filename=dpdpa_compliance_{timestamp}.csv"},
    )


# ──────────────────────────────────────────────
# MySQL Database Records API
# ──────────────────────────────────────────────

@app.route("/api/db-records", methods=["GET"])
def api_db_records():
    """Return all records from personal_data_records in MySQL."""
    filter_type = request.args.get("type")  # optional: ?type=PII or ?type=SPII
    expired_only = request.args.get("expired")  # optional: ?expired=1

    try:
        if expired_only:
            years = int(request.args.get("years", 3))
            records = get_expired_records(years)
        elif filter_type and filter_type.upper() in ("PII", "SPII"):
            records = get_records_by_type(filter_type.upper())
        else:
            records = db_get_all_records()

        return jsonify({"success": True, "count": len(records), "records": records})
    except Exception as e:
        return jsonify({"success": False, "error": str(e), "records": []}), 500


# ──────────────────────────────────────────────
# Run the application
# ──────────────────────────────────────────────
if __name__ == "__main__":
    print("\n PII Sentinel — Enterprise-Wide Personal Data Discovery & Classification")
    print("   Problem Statement 3 · Aligned with India's DPDPA 2023")
    print("   ------------------------------------------------------------------")
    print("   Running at  ->  http://localhost:5000\n")
    app.run(debug=True, host="0.0.0.0", port=5000)
