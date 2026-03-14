"""
local_monitor_agent.py — Lightweight local filesystem monitoring agent.

Watches one or more folders and forwards file movement events to the
central collector API endpoint (/api/file-events).

Run example:
python scanner/local_monitor_agent.py --path "C:/Users/you/Documents" --collector "http://localhost:5000/api/file-events" --user employee1 --system laptop
"""

from __future__ import annotations

import argparse
import json
import os
import time
import urllib.error
import urllib.request
from typing import Dict, Optional

try:
    from watchdog.events import FileSystemEventHandler
    from watchdog.observers import Observer
    _WATCHDOG_IMPORT_ERROR: Optional[Exception] = None
except ImportError as exc:  # watchdog is an optional runtime dependency
    FileSystemEventHandler = object  # type: ignore[assignment]
    Observer = None  # type: ignore[assignment]
    _WATCHDOG_IMPORT_ERROR = exc

from scanner.file_movement_tracker import hash_file_sha256


class LocalFileEventHandler(FileSystemEventHandler):
    def __init__(self, collector_url: str, user_name: str, system_source: str):
        super().__init__()
        self.collector_url = collector_url
        self.user_name = user_name
        self.system_source = system_source

    def _send(self, payload: Dict) -> None:
        body = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            self.collector_url,
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=8) as resp:
                _ = resp.read()
        except urllib.error.URLError as exc:
            print(f"[agent] failed to send event: {exc}")

    def _base_payload(self, src_path: str, event_type: str, metadata: Dict | None = None) -> Dict:
        filename = os.path.basename(src_path) or src_path
        location = src_path
        file_hash = ""

        if event_type != "DELETE" and os.path.isfile(src_path):
            try:
                file_hash = hash_file_sha256(src_path)
            except OSError:
                file_hash = ""

        payload = {
            "file_hash": file_hash,
            "filename": filename,
            "event_type": event_type,
            "user": self.user_name,
            "system_source": self.system_source,
            "location": location,
            "classification": "Unclassified",
            "risk_level": "LOW",
            "metadata": metadata or {},
        }
        return payload

    def on_created(self, event):
        if event.is_directory:
            return
        self._send(self._base_payload(event.src_path, "CREATE", metadata={"agent": "watchdog"}))

    def on_modified(self, event):
        if event.is_directory:
            return
        self._send(self._base_payload(event.src_path, "MODIFY", metadata={"agent": "watchdog"}))

    def on_moved(self, event):
        if event.is_directory:
            return
        payload = self._base_payload(
            event.dest_path,
            "MOVE",
            metadata={
                "agent": "watchdog",
                "from_location": event.src_path,
                "to_location": event.dest_path,
            },
        )
        payload["location"] = event.dest_path
        self._send(payload)

    def on_deleted(self, event):
        if event.is_directory:
            return
        payload = self._base_payload(
            event.src_path,
            "DELETE",
            metadata={"agent": "watchdog", "note": "hash unavailable for deleted files unless pre-cached"},
        )
        # For deletes where hash is unavailable, collector may still accept with explicit hash passed by caller.
        if payload.get("file_hash"):
            self._send(payload)



def run_agent(path: str, collector: str, user_name: str, system_source: str, recursive: bool = True) -> None:
    if Observer is None:
        raise SystemExit(
            "watchdog is required to run the local monitor agent. "
            "Install it with: pip install watchdog (or pip install -r requirements.txt). "
            f"Import error: {_WATCHDOG_IMPORT_ERROR}"
        )

    handler = LocalFileEventHandler(collector, user_name, system_source)
    observer = Observer()
    observer.schedule(handler, path=path, recursive=recursive)
    observer.start()
    print(f"[agent] watching: {path}")
    print(f"[agent] sending to: {collector}")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="PII Sentinel local file movement monitor")
    parser.add_argument("--path", required=True, help="Folder path to monitor")
    parser.add_argument("--collector", default="http://localhost:5000/api/file-events", help="Collector API URL")
    parser.add_argument("--user", default="employee", help="User identity for event attribution")
    parser.add_argument("--system", default="laptop", help="System source label")
    parser.add_argument(
        "--recursive",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Enable recursive monitoring",
    )
    args = parser.parse_args()

    run_agent(
        path=args.path,
        collector=args.collector,
        user_name=args.user,
        system_source=args.system,
        recursive=args.recursive,
    )
