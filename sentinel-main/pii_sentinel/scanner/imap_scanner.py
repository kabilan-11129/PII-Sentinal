"""
imap_scanner.py — IMAP Email Scanner for PII Sentinel

Connects to any IMAP server (Gmail, Outlook, etc.) using an App Password,
fetches emails from the inbox, extracts text from bodies and attachments,
and runs the PII detection pipeline on each.

Usage:
    from scanner.imap_scanner import scan_imap_inbox

    results = scan_imap_inbox(
        email_address = "user@gmail.com",
        password      = "xxxx xxxx xxxx xxxx",   # Gmail App Password
        imap_host     = "imap.gmail.com",
        imap_port     = 993,
        max_emails    = 20,
    )

For Gmail:
    1. Gmail Settings → See all settings → Forwarding and POP/IMAP → Enable IMAP
    2. Google Account → Security → 2-Step Verification → App Passwords
       → Generate one for "Mail / Other device"
    3. Use that 16-char password here (spaces are optional)
"""

import imaplib
import email as email_lib
import email.header
import io
import re
import html
import hashlib
from datetime import datetime

import pandas as pd

from scanner.pii_detector import detect_all_pii, count_pii, total_pii
from scanner.classifier   import classify_all, assess_risk


# ── IMAP host presets ──────────────────────────────────────────────────────────
IMAP_HOSTS = {
    "gmail":   "imap.gmail.com",
    "outlook": "outlook.office365.com",
    "yahoo":   "imap.mail.yahoo.com",
    "icloud":  "imap.mail.me.com",
    "zoho":    "imap.zoho.com",
}


# ─────────────────────────────────────────────────────────────────────────────
# Header decoding helpers
# ─────────────────────────────────────────────────────────────────────────────

def _decode_header(raw: str) -> str:
    """Safely decode an encoded email header like =?utf-8?b?...?="""
    if not raw:
        return ""
    parts = email.header.decode_header(raw)
    decoded = []
    for part, charset in parts:
        if isinstance(part, bytes):
            try:
                decoded.append(part.decode(charset or "utf-8", errors="replace"))
            except Exception:
                decoded.append(part.decode("latin-1", errors="replace"))
        else:
            decoded.append(str(part))
    return " ".join(decoded).strip()


# ─────────────────────────────────────────────────────────────────────────────
# Text extractors per MIME type
# ─────────────────────────────────────────────────────────────────────────────

def _extract_plain(data: bytes, charset: str = "utf-8") -> str:
    try:
        return data.decode(charset or "utf-8", errors="replace")
    except Exception:
        return data.decode("latin-1", errors="replace")


def _extract_html(data: bytes, charset: str = "utf-8") -> str:
    try:
        raw = data.decode(charset or "utf-8", errors="replace")
        try:
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(raw, "lxml")
            return soup.get_text(separator=" ")
        except ImportError:
            # Fallback: strip HTML tags with stdlib html.parser
            from html.parser import HTMLParser as _HP
            class _Stripper(_HP):
                def __init__(self):
                    super().__init__()
                    self._parts = []
                    self._skip = False
                def handle_starttag(self, tag, attrs):
                    if tag in ("script", "style"):
                        self._skip = True
                def handle_endtag(self, tag):
                    if tag in ("script", "style"):
                        self._skip = False
                def handle_data(self, data):
                    if not self._skip and data.strip():
                        self._parts.append(data.strip())
            s = _Stripper()
            s.feed(raw)
            return " ".join(s._parts)
    except Exception:
        return _extract_plain(data, charset)


def _extract_csv(data: bytes) -> str:
    try:
        df = pd.read_csv(io.BytesIO(data))
        return df.to_string(index=False)
    except Exception:
        # Fallback: treat as plain text
        return data.decode("utf-8", errors="replace")


def _extract_excel(data: bytes) -> str:
    try:
        sheets = pd.read_excel(io.BytesIO(data), sheet_name=None)
        parts  = []
        for name, df in sheets.items():
            parts.append(f"[Sheet: {name}]\n{df.to_string(index=False)}")
        return "\n".join(parts)
    except Exception as e:
        return f"[Excel parse error: {e}]"


def _extract_pdf(data: bytes) -> str:
    try:
        import PyPDF2
        reader = PyPDF2.PdfReader(io.BytesIO(data))
        return " ".join(
            (page.extract_text() or "") for page in reader.pages
        )
    except ImportError:
        return "[PDF: install PyPDF2 to extract text]"
    except Exception as e:
        return f"[PDF parse error: {e}]"


_MIME_DISPATCH = {
    "text/plain":  lambda d, cs: _extract_plain(d, cs),
    "text/html":   lambda d, cs: _extract_html(d, cs),
    "text/csv":    lambda d, cs: _extract_csv(d),
    "application/csv":     lambda d, cs: _extract_csv(d),
    "application/pdf":     lambda d, cs: _extract_pdf(d),
    # Excel formats
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet":
        lambda d, cs: _extract_excel(d),
    "application/vnd.ms-excel":
        lambda d, cs: _extract_excel(d),
    "application/octet-stream":
        lambda d, cs: "",   # skip generic binary
}


def _extract_text(mime_type: str, data: bytes, charset: str = "utf-8", filename: str = "") -> str:
    """Route data to the right extractor; guess from filename if mime_type is generic."""
    # Guess from file extension if content-type is unhelpful
    if mime_type == "application/octet-stream" and filename:
        fname = filename.lower()
        if fname.endswith(".csv"):
            return _extract_csv(data)
        if fname.endswith((".xlsx", ".xls")):
            return _extract_excel(data)
        if fname.endswith(".pdf"):
            return _extract_pdf(data)
        if fname.endswith((".txt", ".log", ".md")):
            return _extract_plain(data, charset)

    extractor = _MIME_DISPATCH.get(mime_type)
    if extractor:
        return extractor(data, charset)
    return ""


# ─────────────────────────────────────────────────────────────────────────────
# Email part walker
# ─────────────────────────────────────────────────────────────────────────────

def _walk_parts(msg) -> list:
    """
    Walk all MIME parts of an email and return a list of dicts:
        { mime_type, filename, data (bytes), charset }
    """
    results = []
    for part in msg.walk():
        mime_type = part.get_content_type()
        charset   = part.get_content_charset() or "utf-8"
        filename  = _decode_header(part.get_filename() or "")

        # Skip multipart containers (walk goes deeper)
        if part.get_content_maintype() == "multipart":
            continue
        if part.get("Content-Disposition", "").startswith("multipart"):
            continue

        try:
            payload = part.get_payload(decode=True)
        except Exception:
            payload = None

        if payload:
            results.append({
                "mime_type": mime_type,
                "filename":  filename,
                "data":      payload,
                "charset":   charset,
            })
    return results


# ─────────────────────────────────────────────────────────────────────────────
# Single-email scanner
# ─────────────────────────────────────────────────────────────────────────────

def _scan_message(raw_bytes: bytes) -> dict:
    """
    Parse and scan a single raw email message.

    Returns:
        {
          subject, from_addr, date, snippet,
          pii_results, pii_counts, pii_total,
          classifications, risk_level, risk_reason,
          sources: [ {label, pii_found, pii_count} ]
        }
    """
    msg = email_lib.message_from_bytes(raw_bytes)

    subject   = _decode_header(msg.get("Subject", "(no subject)"))
    from_addr = _decode_header(msg.get("From", "unknown"))
    date_raw  = msg.get("Date", "")

    # ── Walk all MIME parts ───────────────────────────────────────────────────
    all_pii    = {}   # { pii_type: set(matches) }
    sources    = []
    attachment_hashes = []

    for part_info in _walk_parts(msg):
        text = _extract_text(
            part_info["mime_type"],
            part_info["data"],
            part_info["charset"],
            part_info["filename"],
        )
        if not text.strip():
            continue

        pii_found = detect_all_pii(text)
        pii_cnt   = count_pii(pii_found)
        total_cnt = total_pii(pii_found)

        if total_cnt > 0:
            label = part_info["filename"] if part_info["filename"] else f"[email body: {part_info['mime_type']}]"
            content_hash = hashlib.sha256(part_info["data"]).hexdigest()
            sources.append({
                "label":     label,
                "pii_found": pii_found,
                "pii_count": total_cnt,
                "file_hash": content_hash,
                "mime_type": part_info["mime_type"],
            })
            if part_info["filename"]:
                attachment_hashes.append({
                    "filename": part_info["filename"],
                    "file_hash": content_hash,
                    "mime_type": part_info["mime_type"],
                })
            for pii_type, matches in pii_found.items():
                all_pii.setdefault(pii_type, set()).update(matches)

    # Merge: convert sets back to lists
    pii_results = {k: list(v) for k, v in all_pii.items()}
    pii_counts  = count_pii(pii_results)
    pii_total_n = total_pii(pii_results)
    classifications     = classify_all(pii_results)
    risk_level, risk_reason = assess_risk(pii_results)

    # Build a short snippet from the plain-text body for display
    snippet = ""
    for part_info in _walk_parts(msg):
        if part_info["mime_type"] == "text/plain" and not part_info["filename"]:
            snippet = _extract_plain(part_info["data"], part_info["charset"])[:200].strip()
            break

    return {
        "subject":        subject,
        "from_addr":      from_addr,
        "date":           date_raw,
        "snippet":        snippet,
        "pii_results":    pii_results,
        "pii_counts":     pii_counts,
        "pii_total":      pii_total_n,
        "classifications":classifications,
        "risk_level":     risk_level,
        "risk_reason":    risk_reason,
        "sources":        sources,
        "attachment_hashes": attachment_hashes,
    }


# ─────────────────────────────────────────────────────────────────────────────
# Main public function
# ─────────────────────────────────────────────────────────────────────────────

def scan_imap_inbox(
    email_address: str,
    password: str,
    imap_host: str   = "imap.gmail.com",
    imap_port: int   = 993,
    max_emails: int  = 20,
    folder: str      = "INBOX",
) -> list:
    """
    Connect to an IMAP server, fetch the latest `max_emails` from `folder`,
    and run the PII pipeline on each.

    Returns a list of result dicts (one per email) — same shape as
    file_details entries so the Flask endpoint can append them directly.

    Raises:
        ConnectionError  — if IMAP login fails
        ValueError       — if folder doesn't exist
    """
    # Strip spaces from App Password (Google sometimes shows spaces)
    password = password.replace(" ", "")

    # ── Connect ───────────────────────────────────────────────────────────────
    try:
        conn = imaplib.IMAP4_SSL(imap_host, imap_port)
    except Exception as e:
        raise ConnectionError(f"Cannot reach {imap_host}:{imap_port} — {e}")

    # ── Login ─────────────────────────────────────────────────────────────────
    try:
        conn.login(email_address, password)
    except imaplib.IMAP4.error as e:
        raise ConnectionError(
            f"Login failed for {email_address}: {e}. "
            "Make sure IMAP is enabled and you are using an App Password."
        )

    # ── Select folder ─────────────────────────────────────────────────────────
    status, data = conn.select(folder, readonly=True)
    if status != "OK":
        conn.logout()
        raise ValueError(f"Could not open folder '{folder}': {data}")

    # ── Fetch message IDs (most recent first) ─────────────────────────────────
    status, msg_nums = conn.search(None, "ALL")
    if status != "OK":
        conn.logout()
        return []

    all_ids = msg_nums[0].split()
    # Take the last max_emails (most recent)
    ids_to_fetch = all_ids[-max_emails:] if len(all_ids) > max_emails else all_ids
    ids_to_fetch = list(reversed(ids_to_fetch))  # newest first

    # ── Scan each message ─────────────────────────────────────────────────────
    results  = []
    scan_now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    for num in ids_to_fetch:
        try:
            status, raw = conn.fetch(num, "(RFC822)")
            if status != "OK" or not raw or not raw[0]:
                continue
            raw_bytes = raw[0][1] if isinstance(raw[0], tuple) else raw[0]

            msg_data = _scan_message(raw_bytes)

            # Add envelope metadata
            msg_data["scan_time"]        = scan_now
            msg_data["data_source"]      = "email"
            msg_data["storage_location"] = f"IMAP: {imap_host}/{folder}"
            msg_data["data_owner"]       = email_address
            # Use a safe filename for display
            safe_subject = re.sub(r"[^\w\s\-]", "", msg_data["subject"])[:50] or "no-subject"
            msg_data["filename"]         = f"Email: {safe_subject}"
            msg_data["file_size"]        = "—"

            results.append(msg_data)

        except Exception:
            # Skip malformed messages silently
            continue

    conn.close()
    conn.logout()
    return results
