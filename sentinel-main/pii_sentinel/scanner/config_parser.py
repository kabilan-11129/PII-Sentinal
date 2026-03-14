"""
config_parser.py — Parse enterprise scan configuration files.

Accepts CSV, XLSX, or PDF configuration files that define data source
credentials and scanning targets. Extracts structured source entries
from each format and returns a unified list of source configurations.

Expected CSV/XLSX columns:
    SourceType   — email | cloud | folder | database
    Identifier   — email address, provider name, path label, db label
    Credential   — password, access_key:secret_key, oauth_token, user:pass@host, "none"
    PathOrBucket — IMAP host, s3://bucket, drive://folder, /local/path, db_name

Example row:
    email, john@gmail.com, password123, imap.gmail.com
"""

import os
import re
from typing import Dict, List, Optional

import pandas as pd

from scanner.file_parser import parse_pdf


# ── Column name normalization ────────────────────────────────────────────────
_COLUMN_ALIASES = {
    "sourcetype":   "source_type",
    "source_type":  "source_type",
    "source":       "source_type",
    "type":         "source_type",
    "identifier":   "identifier",
    "id":           "identifier",
    "name":         "identifier",
    "credential":   "credential",
    "credentials":  "credential",
    "cred":         "credential",
    "password":     "credential",
    "auth":         "credential",
    "pathorbucket": "path_or_bucket",
    "path_or_bucket": "path_or_bucket",
    "path":         "path_or_bucket",
    "bucket":       "path_or_bucket",
    "host":         "path_or_bucket",
    "target":       "path_or_bucket",
}

_REQUIRED_FIELDS = {"source_type", "identifier", "credential", "path_or_bucket"}


def _normalize_columns(df: pd.DataFrame) -> pd.DataFrame:
    """Rename DataFrame columns to canonical names using alias mapping."""
    rename_map = {}
    for col in df.columns:
        key = col.strip().lower().replace(" ", "_").replace("-", "_")
        if key in _COLUMN_ALIASES:
            rename_map[col] = _COLUMN_ALIASES[key]
    df = df.rename(columns=rename_map)
    return df


def _rows_to_sources(df: pd.DataFrame) -> List[dict]:
    """Convert a normalized DataFrame into a list of source config dicts."""
    df = _normalize_columns(df)

    # Validate required columns exist
    present = set(df.columns)
    missing = _REQUIRED_FIELDS - present
    if missing:
        raise ValueError(f"Configuration file missing required columns: {', '.join(missing)}")

    sources = []
    for _, row in df.iterrows():
        source_type = str(row.get("source_type", "")).strip().lower()
        identifier = str(row.get("identifier", "")).strip()
        credential = str(row.get("credential", "")).strip()
        path_or_bucket = str(row.get("path_or_bucket", "")).strip()

        if not source_type or not identifier:
            continue

        sources.append({
            "source_type": source_type,
            "identifier": identifier,
            "credential": credential,
            "path_or_bucket": path_or_bucket,
        })

    return sources


# ── Format-specific parsers ──────────────────────────────────────────────────

def parse_config_csv(filepath: str) -> List[dict]:
    """Parse a CSV configuration file into source entries."""
    df = pd.read_csv(filepath, dtype=str, keep_default_na=False)
    return _rows_to_sources(df)


def parse_config_xlsx(filepath: str) -> List[dict]:
    """Parse an XLSX configuration file into source entries."""
    df = pd.read_excel(filepath, dtype=str, engine="openpyxl")
    df = df.fillna("")
    return _rows_to_sources(df)


def parse_config_pdf(filepath: str) -> List[dict]:
    """
    Parse a PDF configuration file by extracting text and finding
    tabular rows that match the expected SourceType,Identifier,Credential,Path pattern.
    """
    text = parse_pdf(filepath)
    if not text or text.startswith("[PDF parse error"):
        raise ValueError(f"Could not extract text from PDF: {filepath}")

    lines = text.strip().split("\n")
    sources = []

    for line in lines:
        line = line.strip()
        if not line:
            continue

        # Try comma-separated first, then pipe-separated, then whitespace
        for sep in [",", "|", "\t"]:
            parts = [p.strip() for p in line.split(sep)]
            if len(parts) >= 4:
                source_type = parts[0].lower()
                if source_type in ("email", "cloud", "folder", "database"):
                    sources.append({
                        "source_type": source_type,
                        "identifier": parts[1],
                        "credential": parts[2],
                        "path_or_bucket": parts[3],
                    })
                    break

    return sources


# ── Dispatcher ───────────────────────────────────────────────────────────────

def parse_config_file(filepath: str) -> List[dict]:
    """
    Auto-detect config file format and parse into source entries.

    Supports: .csv, .xlsx, .pdf

    Returns:
        List of dicts, each with keys:
            source_type, identifier, credential, path_or_bucket
    """
    ext = os.path.splitext(filepath)[1].lower()

    if ext == ".csv":
        return parse_config_csv(filepath)
    elif ext == ".xlsx":
        return parse_config_xlsx(filepath)
    elif ext == ".pdf":
        return parse_config_pdf(filepath)
    else:
        raise ValueError(f"Unsupported configuration file format: {ext}. Use CSV, XLSX, or PDF.")


# ── Source classification helpers ────────────────────────────────────────────

def classify_sources(sources: List[dict]) -> Dict[str, List[dict]]:
    """
    Group parsed source entries by type.

    Returns:
        {
            "email": [...],
            "cloud": [...],
            "folder": [...],
            "database": [...]
        }
    """
    classified = {
        "email": [],
        "cloud": [],
        "folder": [],
        "database": [],
    }

    for src in sources:
        st = src["source_type"]
        if st in classified:
            classified[st].append(src)

    return classified


def build_pipeline_config(sources: List[dict]) -> dict:
    """
    Convert parsed source entries into the format expected by the
    existing enterprise scanning infrastructure.

    Returns a config dict compatible with run_enterprise_scan() and
    the org-scan API endpoint.
    """
    classified = classify_sources(sources)
    config = {"sources": {}}

    # Email sources
    for email_src in classified["email"]:
        config["sources"].setdefault("email", {
            "enabled": True,
            "accounts": [],
        })
        config["sources"]["email"]["accounts"].append({
            "email": email_src["identifier"],
            "password": email_src["credential"],
            "imap_host": email_src["path_or_bucket"] or "imap.gmail.com",
            "max_emails": 50,
            "folder": "INBOX",
        })

    # Cloud sources
    for cloud_src in classified["cloud"]:
        config["sources"].setdefault("cloud", {
            "enabled": True,
            "providers": [],
        })

        provider_name = cloud_src["identifier"].lower()
        cred_str = cloud_src["credential"]
        path = cloud_src["path_or_bucket"]

        # Parse credential string  (access_key:secret_key format)
        cred_parts = cred_str.split(":", 1) if ":" in cred_str else [cred_str, ""]

        credentials = {}
        if "s3" in provider_name or "aws" in provider_name:
            provider_type = "s3"
            credentials = {
                "aws_access_key": cred_parts[0],
                "aws_secret_key": cred_parts[1] if len(cred_parts) > 1 else "",
                "bucket_name": path.replace("s3://", ""),
            }
        elif "gdrive" in provider_name or "google" in provider_name:
            provider_type = "gdrive"
            credentials = {
                "service_account_json": cred_str,
                "folder_id": path.replace("drive://", ""),
            }
        elif "azure" in provider_name:
            provider_type = "azure"
            credentials = {
                "connection_string": cred_str,
                "container_name": path.replace("azure://", ""),
            }
        elif "dropbox" in provider_name:
            provider_type = "dropbox"
            credentials = {
                "access_token": cred_str,
                "folder_path": path.replace("dropbox://", ""),
            }
        else:
            provider_type = provider_name
            credentials = {"token": cred_str, "path": path}

        config["sources"]["cloud"]["providers"].append({
            "provider": provider_type,
            "credentials": credentials,
            "max_files": 100,
        })

    # Folder sources
    for folder_src in classified["folder"]:
        config["sources"].setdefault("folders", [])
        config["sources"]["folders"].append({
            "enabled": True,
            "path": folder_src["path_or_bucket"],
            "recursive": True,
            "max_files": 100,
        })

    # Database sources
    for db_src in classified["database"]:
        config["sources"].setdefault("databases", [])
        cred = db_src["credential"]
        path = db_src["path_or_bucket"]

        # Parse database credential: user:password@host format
        db_config = {
            "enabled": True,
            "db_name": path,
            "identifier": db_src["identifier"],
        }

        if cred.lower() == "none" or not cred:
            db_config["db_path"] = path
        elif "@" in cred:
            # user:password@host format
            user_pass, host = cred.rsplit("@", 1)
            parts = user_pass.split(":", 1)
            db_config["user"] = parts[0]
            db_config["password"] = parts[1] if len(parts) > 1 else ""
            db_config["host"] = host
            db_config["db_path"] = path
        else:
            db_config["db_path"] = path

        config["sources"]["databases"].append(db_config)

    return config
