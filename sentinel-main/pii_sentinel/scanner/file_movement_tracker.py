"""
file_movement_tracker.py — Enterprise file lineage + movement tracking.

This module provides:
- SHA-256 file fingerprinting
- Append-only event logging in SQLite
- File timeline reconstruction
- Simple lineage graph materialization (nodes + edges)
- Rule-based breach alerts aligned with DPDPA controls
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import sqlite3
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple


TRACKER_DB_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "..",
    "database",
    "file_lineage.db",
)

EVENT_TYPES = {
    "CREATE",
    "READ",
    "COPY",
    "MOVE",
    "DOWNLOAD",
    "SHARE",
    "MODIFY",
    "DELETE",
}

SENSITIVE_KEYWORDS = {"aadhaar", "pan", "financial", "bank", "upi", "account"}


def _now_iso() -> str:
    return datetime.now().isoformat(timespec="seconds")


def _conn() -> sqlite3.Connection:
    db_dir = os.path.dirname(os.path.abspath(TRACKER_DB_PATH))
    os.makedirs(db_dir, exist_ok=True)
    conn = sqlite3.connect(TRACKER_DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_tracker_db() -> None:
    with _conn() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS file_event_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                file_hash TEXT NOT NULL,
                filename TEXT NOT NULL,
                event_type TEXT NOT NULL,
                user_name TEXT NOT NULL,
                system_source TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                location TEXT,
                classification TEXT,
                risk_level TEXT,
                metadata_json TEXT
            )
            """
        )
        conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_event_hash_ts
            ON file_event_log(file_hash, timestamp)
            """
        )
        conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_event_user_ts
            ON file_event_log(user_name, timestamp)
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS file_profiles (
                file_hash TEXT PRIMARY KEY,
                filename TEXT NOT NULL,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                classification TEXT,
                risk_level TEXT,
                pii_types_json TEXT,
                last_location TEXT,
                last_system TEXT,
                last_user TEXT
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS lineage_edges (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                file_hash TEXT NOT NULL,
                from_node TEXT NOT NULL,
                to_node TEXT NOT NULL,
                edge_type TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                metadata_json TEXT
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS breach_alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                file_hash TEXT,
                filename TEXT,
                alert_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                message TEXT NOT NULL,
                user_name TEXT,
                system_source TEXT,
                timestamp TEXT NOT NULL,
                metadata_json TEXT
            )
            """
        )


def hash_file_sha256(file_path: str) -> str:
    digest = hashlib.sha256()
    with open(file_path, "rb") as f:
        while True:
            chunk = f.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def hash_bytes_sha256(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def hash_base64_sha256(content_base64: str) -> str:
    raw = base64.b64decode(content_base64)
    return hash_bytes_sha256(raw)


def _normalize_event_type(event_type: str) -> str:
    ev = (event_type or "").strip().upper()
    if ev not in EVENT_TYPES:
        raise ValueError(f"Unsupported event_type '{event_type}'. Allowed: {sorted(EVENT_TYPES)}")
    return ev


def _classification_from_pii(pii_types: Optional[List[str]], fallback: str = "") -> str:
    if pii_types:
        compact = [str(p).strip() for p in pii_types if str(p).strip()]
        if compact:
            return ", ".join(sorted(set(compact)))
    return (fallback or "Unclassified").strip() or "Unclassified"


def _is_sensitive(classification: str, risk_level: str, pii_types: Optional[List[str]]) -> bool:
    c = (classification or "").lower()
    r = (risk_level or "").upper()
    if r in {"HIGH", "CRITICAL"}:
        return True
    if pii_types:
        for p in pii_types:
            if str(p).strip().lower() in SENSITIVE_KEYWORDS:
                return True
    return any(k in c for k in SENSITIVE_KEYWORDS)


def _insert_alert(
    conn: sqlite3.Connection,
    *,
    file_hash: str,
    filename: str,
    alert_type: str,
    severity: str,
    message: str,
    user_name: str,
    system_source: str,
    metadata: Optional[dict] = None,
) -> dict:
    ts = _now_iso()
    conn.execute(
        """
        INSERT INTO breach_alerts(
            file_hash, filename, alert_type, severity, message,
            user_name, system_source, timestamp, metadata_json
        )
        VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            file_hash,
            filename,
            alert_type,
            severity,
            message,
            user_name,
            system_source,
            ts,
            json.dumps(metadata or {}, ensure_ascii=True),
        ),
    )
    return {
        "file_hash": file_hash,
        "filename": filename,
        "alert_type": alert_type,
        "severity": severity,
        "message": message,
        "user_name": user_name,
        "system_source": system_source,
        "timestamp": ts,
        "metadata": metadata or {},
    }


def _append_edge(
    conn: sqlite3.Connection,
    *,
    file_hash: str,
    from_node: str,
    to_node: str,
    edge_type: str,
    metadata: Optional[dict] = None,
) -> None:
    conn.execute(
        """
        INSERT INTO lineage_edges(file_hash, from_node, to_node, edge_type, timestamp, metadata_json)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            file_hash,
            from_node,
            to_node,
            edge_type,
            _now_iso(),
            json.dumps(metadata or {}, ensure_ascii=True),
        ),
    )


def append_file_event(
    *,
    file_hash: str,
    filename: str,
    event_type: str,
    user_name: str,
    system_source: str,
    location: str,
    classification: str = "Unclassified",
    risk_level: str = "LOW",
    pii_types: Optional[List[str]] = None,
    timestamp: Optional[str] = None,
    metadata: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Append one immutable file event and run breach-detection rules."""
    init_tracker_db()
    ev = _normalize_event_type(event_type)
    ts = timestamp or _now_iso()
    safe_meta = metadata or {}
    class_label = _classification_from_pii(pii_types, fallback=classification)
    risk = (risk_level or "LOW").upper()

    alerts: List[dict] = []

    with _conn() as conn:
        conn.execute(
            """
            INSERT INTO file_event_log(
                file_hash, filename, event_type, user_name,
                system_source, timestamp, location,
                classification, risk_level, metadata_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                file_hash,
                filename,
                ev,
                user_name,
                system_source,
                ts,
                location,
                class_label,
                risk,
                json.dumps(safe_meta, ensure_ascii=True),
            ),
        )

        first_seen = ts
        existing = conn.execute(
            "SELECT first_seen FROM file_profiles WHERE file_hash = ?",
            (file_hash,),
        ).fetchone()
        if existing:
            first_seen = str(existing["first_seen"])

        conn.execute(
            """
            INSERT INTO file_profiles(
                file_hash, filename, first_seen, last_seen,
                classification, risk_level, pii_types_json,
                last_location, last_system, last_user
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(file_hash) DO UPDATE SET
                filename = excluded.filename,
                last_seen = excluded.last_seen,
                classification = excluded.classification,
                risk_level = excluded.risk_level,
                pii_types_json = excluded.pii_types_json,
                last_location = excluded.last_location,
                last_system = excluded.last_system,
                last_user = excluded.last_user
            """,
            (
                file_hash,
                filename,
                first_seen,
                ts,
                class_label,
                risk,
                json.dumps(pii_types or [], ensure_ascii=True),
                location,
                system_source,
                user_name,
            ),
        )

        # Build lineage graph edges
        _append_edge(
            conn,
            file_hash=file_hash,
            from_node=f"user:{user_name}",
            to_node=f"file:{file_hash}",
            edge_type=ev.lower(),
            metadata={"filename": filename, "system": system_source},
        )
        _append_edge(
            conn,
            file_hash=file_hash,
            from_node=f"system:{system_source}",
            to_node=f"file:{file_hash}",
            edge_type=ev.lower(),
            metadata={"location": location},
        )

        from_loc = str(safe_meta.get("from_location", "")).strip()
        to_loc = str(safe_meta.get("to_location", "")).strip()
        if from_loc and to_loc and from_loc != to_loc and ev in {"MOVE", "COPY", "DOWNLOAD", "SHARE"}:
            _append_edge(
                conn,
                file_hash=file_hash,
                from_node=f"location:{from_loc}",
                to_node=f"location:{to_loc}",
                edge_type=ev.lower(),
                metadata={"filename": filename},
            )

        sensitive = _is_sensitive(class_label, risk, pii_types)

        # Rule 1: External share of Aadhaar/PAN/sensitive data.
        external = bool(safe_meta.get("external", False))
        if ev == "SHARE" and external and sensitive:
            alerts.append(
                _insert_alert(
                    conn,
                    file_hash=file_hash,
                    filename=filename,
                    alert_type="EXTERNAL_SENSITIVE_SHARE",
                    severity="CRITICAL",
                    message="Sensitive file shared externally.",
                    user_name=user_name,
                    system_source=system_source,
                    metadata={"event": ev, "classification": class_label, **safe_meta},
                )
            )

        # Rule 2: >50 sensitive downloads by same user in 5 minutes.
        if ev == "DOWNLOAD" and sensitive:
            window_start = (datetime.fromisoformat(ts) - timedelta(minutes=5)).isoformat(timespec="seconds")
            row = conn.execute(
                """
                SELECT COUNT(1) AS n
                FROM file_event_log
                WHERE user_name = ?
                  AND event_type = 'DOWNLOAD'
                  AND timestamp >= ?
                  AND (
                        UPPER(risk_level) IN ('HIGH', 'CRITICAL')
                        OR LOWER(classification) LIKE '%aadhaar%'
                        OR LOWER(classification) LIKE '%pan%'
                        OR LOWER(classification) LIKE '%financial%'
                  )
                """,
                (user_name, window_start),
            ).fetchone()
            if int(row["n"]) > 50:
                alerts.append(
                    _insert_alert(
                        conn,
                        file_hash=file_hash,
                        filename=filename,
                        alert_type="MASS_SENSITIVE_DOWNLOAD",
                        severity="HIGH",
                        message=f"User {user_name} downloaded >50 sensitive files within 5 minutes.",
                        user_name=user_name,
                        system_source=system_source,
                        metadata={"downloads_in_window": int(row["n"]), "window_minutes": 5},
                    )
                )

        # Rule 3: Sensitive file appears in a new system unexpectedly.
        if sensitive and ev != "CREATE":
            seen_in_current = conn.execute(
                """
                SELECT COUNT(1) AS n
                FROM file_event_log
                WHERE file_hash = ? AND system_source = ?
                """,
                (file_hash, system_source),
            ).fetchone()
            is_new_system = int(seen_in_current["n"]) == 1
            expected_systems = [str(s).strip() for s in safe_meta.get("expected_systems", []) if str(s).strip()]
            explicitly_expected = bool(safe_meta.get("is_expected", False))
            if is_new_system:
                unexpected = (expected_systems and system_source not in expected_systems) or (not explicitly_expected and not expected_systems)
                if unexpected:
                    alerts.append(
                        _insert_alert(
                            conn,
                            file_hash=file_hash,
                            filename=filename,
                            alert_type="UNEXPECTED_SYSTEM_PROPAGATION",
                            severity="MEDIUM",
                            message=f"Sensitive file appeared in new system '{system_source}'.",
                            user_name=user_name,
                            system_source=system_source,
                            metadata={"expected_systems": expected_systems, **safe_meta},
                        )
                    )

        conn.commit()

    return {
        "success": True,
        "event": {
            "file_hash": file_hash,
            "filename": filename,
            "event_type": ev,
            "user": user_name,
            "system_source": system_source,
            "timestamp": ts,
            "location": location,
            "classification": class_label,
            "risk_level": risk,
            "metadata": safe_meta,
        },
        "alerts": alerts,
    }


def ingest_file_observation(
    *,
    file_path: Optional[str] = None,
    content_base64: Optional[str] = None,
    file_hash: Optional[str] = None,
    filename: str,
    event_type: str,
    user_name: str,
    system_source: str,
    location: str,
    classification: str = "Unclassified",
    risk_level: str = "LOW",
    pii_types: Optional[List[str]] = None,
    metadata: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Resolve SHA-256 fingerprint from content/path/hash and append the event."""
    resolved_hash = (file_hash or "").strip()

    if not resolved_hash and file_path:
        resolved_hash = hash_file_sha256(file_path)
    elif not resolved_hash and content_base64:
        resolved_hash = hash_base64_sha256(content_base64)

    if not resolved_hash:
        raise ValueError("Provide one of: file_hash, file_path, or content_base64")

    return append_file_event(
        file_hash=resolved_hash,
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


def get_event_log(file_hash: Optional[str] = None, limit: int = 500) -> List[dict]:
    init_tracker_db()
    q = """
        SELECT file_hash, filename, event_type, user_name, system_source,
               timestamp, location, classification, risk_level, metadata_json
        FROM file_event_log
    """
    params: Tuple[Any, ...] = ()
    if file_hash:
        q += " WHERE file_hash = ?"
        params = (file_hash,)
    q += " ORDER BY timestamp DESC LIMIT ?"
    params = (*params, int(limit))

    with _conn() as conn:
        rows = conn.execute(q, params).fetchall()
    out = []
    for r in rows:
        out.append(
            {
                "file_hash": r["file_hash"],
                "filename": r["filename"],
                "event_type": r["event_type"],
                "user": r["user_name"],
                "system_source": r["system_source"],
                "timestamp": r["timestamp"],
                "location": r["location"],
                "classification": r["classification"],
                "risk_level": r["risk_level"],
                "metadata": json.loads(r["metadata_json"] or "{}"),
            }
        )
    return out


def get_file_timeline(file_hash: str) -> dict:
    init_tracker_db()
    with _conn() as conn:
        profile = conn.execute(
            "SELECT * FROM file_profiles WHERE file_hash = ?",
            (file_hash,),
        ).fetchone()
        events = conn.execute(
            """
            SELECT event_type, user_name, system_source, timestamp, location, metadata_json
            FROM file_event_log
            WHERE file_hash = ?
            ORDER BY timestamp ASC
            """,
            (file_hash,),
        ).fetchall()

    if not profile:
        return {"success": False, "message": f"No tracked file for hash {file_hash}"}

    timeline = []
    for e in events:
        timeline.append(
            {
                "timestamp": e["timestamp"],
                "event_type": e["event_type"],
                "user": e["user_name"],
                "system_source": e["system_source"],
                "location": e["location"],
                "metadata": json.loads(e["metadata_json"] or "{}"),
            }
        )

    return {
        "success": True,
        "file": {
            "file_hash": profile["file_hash"],
            "filename": profile["filename"],
            "classification": profile["classification"],
            "risk_level": profile["risk_level"],
            "first_seen": profile["first_seen"],
            "last_seen": profile["last_seen"],
            "last_location": profile["last_location"],
            "last_system": profile["last_system"],
        },
        "timeline": timeline,
    }


def get_lineage_graph(file_hash: Optional[str] = None) -> dict:
    init_tracker_db()
    with _conn() as conn:
        edge_query = "SELECT file_hash, from_node, to_node, edge_type, timestamp, metadata_json FROM lineage_edges"
        params: Tuple[Any, ...] = ()
        if file_hash:
            edge_query += " WHERE file_hash = ?"
            params = (file_hash,)
        edge_query += " ORDER BY timestamp ASC"
        edge_rows = conn.execute(edge_query, params).fetchall()

        if file_hash:
            profile_rows = conn.execute(
                "SELECT file_hash, filename, classification, risk_level FROM file_profiles WHERE file_hash = ?",
                (file_hash,),
            ).fetchall()
        else:
            profile_rows = conn.execute(
                "SELECT file_hash, filename, classification, risk_level FROM file_profiles"
            ).fetchall()

    nodes = {}
    for p in profile_rows:
        key = f"file:{p['file_hash']}"
        nodes[key] = {
            "id": key,
            "type": "file",
            "file_hash": p["file_hash"],
            "filename": p["filename"],
            "classification": p["classification"],
            "risk_level": p["risk_level"],
        }

    edges = []
    for e in edge_rows:
        from_node = e["from_node"]
        to_node = e["to_node"]
        if from_node not in nodes:
            node_type = from_node.split(":", 1)[0]
            nodes[from_node] = {"id": from_node, "type": node_type, "label": from_node.split(":", 1)[-1]}
        if to_node not in nodes:
            node_type = to_node.split(":", 1)[0]
            nodes[to_node] = {"id": to_node, "type": node_type, "label": to_node.split(":", 1)[-1]}

        edges.append(
            {
                "file_hash": e["file_hash"],
                "from": from_node,
                "to": to_node,
                "edge_type": e["edge_type"],
                "timestamp": e["timestamp"],
                "metadata": json.loads(e["metadata_json"] or "{}"),
            }
        )

    return {
        "nodes": list(nodes.values()),
        "edges": edges,
        "counts": {"nodes": len(nodes), "edges": len(edges)},
    }


def get_breach_alerts(limit: int = 100) -> List[dict]:
    init_tracker_db()
    with _conn() as conn:
        rows = conn.execute(
            """
            SELECT file_hash, filename, alert_type, severity, message,
                   user_name, system_source, timestamp, metadata_json
            FROM breach_alerts
            ORDER BY timestamp DESC
            LIMIT ?
            """,
            (int(limit),),
        ).fetchall()
    return [
        {
            "file_hash": r["file_hash"],
            "filename": r["filename"],
            "alert_type": r["alert_type"],
            "severity": r["severity"],
            "message": r["message"],
            "user": r["user_name"],
            "system_source": r["system_source"],
            "timestamp": r["timestamp"],
            "metadata": json.loads(r["metadata_json"] or "{}"),
        }
        for r in rows
    ]


def tracker_summary() -> dict:
    init_tracker_db()
    with _conn() as conn:
        a = conn.execute("SELECT COUNT(1) AS n FROM file_profiles").fetchone()
        b = conn.execute("SELECT COUNT(1) AS n FROM file_event_log").fetchone()
        c = conn.execute("SELECT COUNT(1) AS n FROM breach_alerts").fetchone()
        d = conn.execute(
            """
            SELECT system_source, COUNT(1) AS n
            FROM file_event_log
            GROUP BY system_source
            ORDER BY n DESC
            """
        ).fetchall()
    return {
        "tracked_files": int(a["n"]),
        "events": int(b["n"]),
        "alerts": int(c["n"]),
        "by_system": [{"system": r["system_source"], "events": int(r["n"])} for r in d],
    }
