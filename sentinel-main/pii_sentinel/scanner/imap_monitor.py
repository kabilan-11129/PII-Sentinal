"""
imap_monitor.py — Real-Time IMAP Inbox Monitor for PII Sentinel

Runs a background daemon thread that polls an IMAP mailbox for new emails
at a configurable interval. Each new email is immediately scanned for PII
and events are pushed to a thread-safe queue consumed by the SSE endpoint.

Architecture:
  app.py creates one global IMAPMonitor instance.
  POST /api/realtime/start  → monitor.start(...)
  POST /api/realtime/stop   → monitor.stop()
  GET  /api/realtime/stream → SSE generator drains monitor.drain_events()

How new-email detection works:
  On start, we record the full set of existing UIDs as a "baseline".
  Every poll_interval seconds we re-SELECT the folder and fetch all UIDs.
  Any UID not in the baseline set is a new email — we fetch, scan, and emit.
"""

import imaplib
import threading
import queue
import time
import re
from datetime import datetime

from scanner.imap_scanner   import _scan_message
from reports.report_generator import build_rows


# ─────────────────────────────────────────────────────────────────────────────
class IMAPMonitor:
    """Thread-safe, real-time IMAP inbox monitor."""

    def __init__(self):
        self._stop_event   = threading.Event()
        self._thread       = None
        self._event_queue  = queue.Queue(maxsize=500)
        self.active        = False
        self.config        = {}
        self.stats         = {
            "scanned":    0,
            "pii_found":  0,
            "clean":      0,
            "errors":     0,
            "started_at": None,
        }
        # References to the Flask app's in-memory stores (set at start())
        self._stores = None

    # ── Public API ────────────────────────────────────────────────────────────

    def start(
        self,
        email_address: str,
        password:      str,
        imap_host:     str  = "imap.gmail.com",
        imap_port:     int  = 993,
        folder:        str  = "INBOX",
        poll_interval: int  = 10,
        stores:        dict = None,   # {"scan_store": [], "file_details": [], "scan_activity": []}
    ) -> None:
        """Start the background monitor thread. Idempotent — calling again is a no-op."""
        if self.active:
            return

        self._stop_event.clear()
        self.active  = True
        self._stores = stores or {}
        self.config  = {
            "email":         email_address,
            "imap_host":     imap_host,
            "imap_port":     imap_port,
            "folder":        folder,
            "poll_interval": poll_interval,
        }
        self.stats = {
            "scanned":    0,
            "pii_found":  0,
            "clean":      0,
            "errors":     0,
            "started_at": datetime.now().isoformat(),
        }
        # Drain stale events from previous run
        self._drain_internal()

        self._thread = threading.Thread(
            target=self._monitor_loop,
            args=(email_address, password, imap_host, imap_port, folder, poll_interval),
            daemon=True,
            name="imap-monitor",
        )
        self._thread.start()

    def stop(self) -> None:
        """Signal the background thread to stop; returns immediately."""
        self._stop_event.set()
        self.active = False

    def drain_events(self, max_events: int = 30) -> list:
        """Non-blocking drain of up to max_events from the SSE queue."""
        out = []
        for _ in range(max_events):
            try:
                out.append(self._event_queue.get_nowait())
            except queue.Empty:
                break
        return out

    def status(self) -> dict:
        return {
            "active": self.active,
            "config": {k: v for k, v in self.config.items() if k != "password"},
            "stats":  self.stats,
        }

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _drain_internal(self):
        while not self._event_queue.empty():
            try:
                self._event_queue.get_nowait()
            except queue.Empty:
                break

    def _emit(self, event_type: str, **payload):
        """Push one SSE-ready event dict into the queue (drops if full)."""
        try:
            self._event_queue.put_nowait({
                "type": event_type,
                "ts":   datetime.now().isoformat(),
                **payload,
            })
        except queue.Full:
            pass

    # ── Background thread ─────────────────────────────────────────────────────

    def _monitor_loop(
        self,
        email_address: str,
        password:      str,
        imap_host:     str,
        imap_port:     int,
        folder:        str,
        poll_interval: int,
    ) -> None:
        """Main loop: connect → baseline → poll for new UIDs → scan → emit."""
        password = password.replace(" ", "")

        # ── Connect ───────────────────────────────────────────────────────────
        try:
            conn = imaplib.IMAP4_SSL(imap_host, imap_port)
        except Exception as e:
            self._emit("error", message=f"Cannot connect to {imap_host}: {e}")
            self.active = False
            return

        # ── Login ─────────────────────────────────────────────────────────────
        try:
            conn.login(email_address, password)
        except imaplib.IMAP4.error as e:
            self._emit("error", message=f"Login failed for {email_address}: {e}")
            self.active = False
            return

        # ── Select folder ─────────────────────────────────────────────────────
        status, _ = conn.select(folder, readonly=True)
        if status != "OK":
            self._emit("error", message=f"Cannot open folder '{folder}'")
            try:
                conn.logout()
            except Exception:
                pass
            self.active = False
            return

        # ── Record baseline UIDs (emails that existed before monitoring began) ─
        status, data = conn.uid("search", None, "ALL")
        seen_uids = set(data[0].split()) if status == "OK" and data[0] else set()

        self._emit(
            "connected",
            email    = email_address,
            host     = imap_host,
            folder   = folder,
            interval = poll_interval,
            message  = (
                f"Monitoring {folder} on {imap_host} every {poll_interval}s — "
                f"{len(seen_uids)} existing emails ignored as baseline."
            ),
        )

        # ── Poll loop ─────────────────────────────────────────────────────────
        poll_count = 0
        while not self._stop_event.is_set():
            # Interruptible sleep: wakes immediately if stop() is called
            self._stop_event.wait(poll_interval)
            if self._stop_event.is_set():
                break

            poll_count += 1

            try:
                # NOOP keepalive every 6 polls (~1 min at 10s interval)
                if poll_count % 6 == 0:
                    conn.noop()

                # Refresh folder state
                conn.select(folder, readonly=True)

                status, data = conn.uid("search", None, "ALL")
                if status != "OK":
                    continue

                current_uids = set(data[0].split()) if data[0] else set()
                new_uids     = current_uids - seen_uids

                if not new_uids:
                    self._emit("heartbeat", message="Watching — no new emails")
                    continue

                # Process each new email newest-first
                for uid in sorted(new_uids, reverse=True):
                    if self._stop_event.is_set():
                        break
                    try:
                        self._process_uid(conn, uid, email_address)
                    except Exception as e:
                        self.stats["errors"] += 1
                        self._emit("error", message=f"Scan error for UID {uid}: {e}")

                seen_uids = current_uids

            except imaplib.IMAP4.abort:
                # Server closed connection — try reconnect once
                self._emit("info", message="Connection dropped — reconnecting…")
                try:
                    conn = imaplib.IMAP4_SSL(imap_host, imap_port)
                    conn.login(email_address, password)
                    conn.select(folder, readonly=True)
                    self._emit("info", message="Reconnected successfully.")
                except Exception as e2:
                    self._emit("error", message=f"Reconnect failed: {e2}")
                    break

            except Exception as e:
                self.stats["errors"] += 1
                self._emit("error", message=f"Poll error: {e}")

        # ── Cleanup ───────────────────────────────────────────────────────────
        try:
            conn.close()
            conn.logout()
        except Exception:
            pass

        self._emit("stopped", message="Real-time monitor stopped.")
        self.active = False

    def _process_uid(self, conn, uid: bytes, email_address: str) -> None:
        """Fetch, scan, store, and emit a single email by UID."""
        status, raw = conn.uid("fetch", uid, "(RFC822)")
        if status != "OK" or not raw or not raw[0]:
            return

        raw_bytes = raw[0][1] if isinstance(raw[0], tuple) else raw[0]
        result    = _scan_message(raw_bytes)

        pii_total  = result.get("pii_total", 0)
        risk_level = result.get("risk_level", "NONE")
        subject    = result.get("subject", "(no subject)")
        from_addr  = result.get("from_addr", "unknown")

        safe_sub  = re.sub(r"[^\w\s\-]", "", subject)[:50] or "no-subject"
        filename  = f"Email: {safe_sub}"
        scan_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        storage   = f"IMAP LIVE: {self.config.get('imap_host', '')}"

        # ── Write to Flask in-memory stores (lists passed by reference) ───────
        if self._stores:
            rows = build_rows(filename, result["pii_results"], scan_time, email_address)
            for row in rows:
                row["storage_location"] = storage

            scan_store    = self._stores.get("scan_store")
            file_details  = self._stores.get("file_details")
            scan_activity = self._stores.get("scan_activity")

            if scan_store is not None:
                scan_store.extend(rows)

            if file_details is not None:
                file_details.append({
                    "filename":         filename,
                    "data_source":      "email",
                    "storage_location": storage,
                    "data_owner":       email_address,
                    "file_size":        "—",
                    "pii_results":      result["pii_results"],
                    "pii_counts":       result["pii_counts"],
                    "pii_total":        pii_total,
                    "classifications":  result["classifications"],
                    "risk_level":       risk_level,
                    "risk_reason":      result.get("risk_reason", ""),
                    "scan_time":        scan_time,
                    "email_from":       from_addr,
                    "email_subject":    subject,
                    "email_snippet":    result.get("snippet", ""),
                })

            if scan_activity is not None:
                scan_activity.append({
                    "time":       scan_time,
                    "filename":   filename,
                    "risk_level": risk_level,
                    "pii_total":  pii_total,
                    "action":     f"LIVE: {filename} — {pii_total} PII ({risk_level} risk)",
                })

        # ── Update stats ──────────────────────────────────────────────────────
        self.stats["scanned"] += 1
        if pii_total > 0:
            self.stats["pii_found"] += 1
        else:
            self.stats["clean"] += 1

        # ── Emit SSE event ────────────────────────────────────────────────────
        RISK_ICONS = {
            "CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡",
            "LOW": "🟢",      "NONE": "⚪",
        }
        self._emit(
            "new_email",
            subject   = subject,
            from_addr = from_addr,
            filename  = filename,
            pii_total = pii_total,
            risk_level= risk_level,
            risk_icon = RISK_ICONS.get(risk_level, "⚪"),
            pii_types = list(result["pii_results"].keys()),
            scan_time = scan_time,
            stats     = dict(self.stats),
        )
