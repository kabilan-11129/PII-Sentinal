"""
cloud_scanner.py — Cloud Storage Connector for PII Sentinel.

Supported providers:
  • AWS S3          — boto3  (pip install boto3)
  • Google Drive    — google-api-python-client  (pip install google-api-python-client google-auth)
  • Azure Blob      — azure-storage-blob  (pip install azure-storage-blob)
  • Dropbox         — dropbox SDK  (pip install dropbox)

Each connector:
  1. Authenticates with the provider using credentials from the request
  2. Lists files in the specified bucket / folder (up to max_files)
  3. Downloads each supported file into a temporary directory
  4. Returns a list of (local_path, cloud_path) tuples for the PII pipeline
  5. Caller is responsible for cleaning up the temp directory

No credentials are stored — they are only used for the duration of the request.
"""

import io
import os
import tempfile

# ──────────────────────────────────────────────────────
# Supported cloud file extensions (same as ALLOWED_EXTENSIONS)
# ──────────────────────────────────────────────────────
_CLOUD_EXTS = {
    ".txt", ".log", ".md",
    ".csv", ".xlsx", ".xls", ".ods",
    ".pdf", ".docx", ".pptx", ".rtf", ".odt",
    ".json", ".xml",
    ".html", ".htm",
    ".eml", ".msg",
    ".zip", ".tar", ".gz", ".tgz",
}


def _is_supported(filename: str) -> bool:
    ext = os.path.splitext(filename)[1].lower()
    return ext in _CLOUD_EXTS


# ══════════════════════════════════════════════════════
# AWS S3
# ══════════════════════════════════════════════════════

def scan_s3(credentials: dict, max_files: int = 100) -> tuple:
    """
    List and download supported files from an AWS S3 bucket.

    credentials keys:
        aws_access_key  — IAM access key ID
        aws_secret_key  — IAM secret access key
        aws_region      — e.g. "us-east-1"  (default: us-east-1)
        bucket_name     — S3 bucket name
        prefix          — optional key prefix / folder (default: "")

    Returns: (tmp_dir: str, files: list[dict{"local", "cloud"}], error: str|None)
    """
    try:
        import boto3
        from botocore.exceptions import BotoCoreError, ClientError
    except ImportError:
        return None, [], "boto3 not installed. Run: pip install boto3"

    access_key  = credentials.get("aws_access_key", "").strip()
    secret_key  = credentials.get("aws_secret_key", "").strip()
    region      = credentials.get("aws_region", "us-east-1").strip() or "us-east-1"
    bucket      = credentials.get("bucket_name", "").strip()
    prefix      = credentials.get("prefix", "").strip()

    if not access_key or not secret_key:
        return None, [], "AWS access key and secret key are required."
    if not bucket:
        return None, [], "S3 bucket name is required."

    try:
        s3 = boto3.client(
            "s3",
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
            region_name=region,
        )

        # Paginate through object listing
        paginator = s3.get_paginator("list_objects_v2")
        pages = paginator.paginate(Bucket=bucket, Prefix=prefix)

        supported_keys = []
        for page in pages:
            for obj in page.get("Contents", []):
                key = obj["Key"]
                if key.endswith("/"):          # skip "folder" entries
                    continue
                if _is_supported(key):
                    supported_keys.append(key)
                if len(supported_keys) >= max_files:
                    break
            if len(supported_keys) >= max_files:
                break

        if not supported_keys:
            return None, [], None  # no error, just no matching files

        tmp_dir = tempfile.mkdtemp(prefix="pii_s3_")
        downloaded = []

        for key in supported_keys:
            filename = os.path.basename(key) or key.replace("/", "_")
            local_path = os.path.join(tmp_dir, filename)
            try:
                s3.download_file(bucket, key, local_path)
                downloaded.append({"local": local_path, "cloud": f"s3://{bucket}/{key}"})
            except (BotoCoreError, ClientError) as e:
                # Skip files we can't download
                continue

        return tmp_dir, downloaded, None

    except (BotoCoreError, ClientError) as e:
        return None, [], f"S3 error: {e}"
    except Exception as e:
        return None, [], f"Unexpected error: {e}"


# ══════════════════════════════════════════════════════
# Google Drive
# ══════════════════════════════════════════════════════

def scan_gdrive(credentials: dict, max_files: int = 100) -> tuple:
    """
    List and download supported files from Google Drive.

    credentials keys:
        service_account_json  — JSON string of service account key file
        folder_id             — Google Drive folder ID (optional; defaults to root)

    Returns: (tmp_dir: str, files: list[dict], error: str|None)
    """
    try:
        from google.oauth2 import service_account
        from googleapiclient.discovery import build
        from googleapiclient.http import MediaIoBaseDownload
    except ImportError:
        return None, [], (
            "google-api-python-client / google-auth not installed.\n"
            "Run: pip install google-api-python-client google-auth"
        )

    sa_json   = credentials.get("service_account_json", "").strip()
    folder_id = credentials.get("folder_id", "").strip()

    if not sa_json:
        return None, [], "service_account_json is required for Google Drive scanning."

    try:
        import json as _json
        sa_info = _json.loads(sa_json)
        scopes  = ["https://www.googleapis.com/auth/drive.readonly"]
        creds   = service_account.Credentials.from_service_account_info(sa_info, scopes=scopes)
        service = build("drive", "v3", credentials=creds, cache_discovery=False)

        # Build query
        query = "trashed = false"
        if folder_id:
            query += f" and '{folder_id}' in parents"

        results = service.files().list(
            q=query,
            pageSize=max_files,
            fields="files(id, name, mimeType)",
        ).execute()

        files = results.get("files", [])
        supported = [f for f in files if _is_supported(f["name"])]

        if not supported:
            return None, [], None

        tmp_dir    = tempfile.mkdtemp(prefix="pii_gdrive_")
        downloaded = []

        for f in supported[:max_files]:
            local_path = os.path.join(tmp_dir, f["name"])
            try:
                request = service.files().get_media(fileId=f["id"])
                buf = io.FileIO(local_path, "wb")
                downloader = MediaIoBaseDownload(buf, request)
                done = False
                while not done:
                    _, done = downloader.next_chunk()
                buf.close()
                downloaded.append({
                    "local": local_path,
                    "cloud": f"gdrive://{f['id']}/{f['name']}",
                })
            except Exception:
                continue

        return tmp_dir, downloaded, None

    except Exception as e:
        return None, [], f"Google Drive error: {e}"


# ══════════════════════════════════════════════════════
# Azure Blob Storage
# ══════════════════════════════════════════════════════

def scan_azure(credentials: dict, max_files: int = 100) -> tuple:
    """
    List and download supported files from Azure Blob Storage.

    credentials keys:
        connection_string  — Azure storage connection string  OR
        account_name       — Storage account name (used with account_key)
        account_key        — Storage account key
        container_name     — Container name
        prefix             — Blob name prefix / virtual folder (optional)

    Returns: (tmp_dir: str, files: list[dict], error: str|None)
    """
    try:
        from azure.storage.blob import BlobServiceClient
    except ImportError:
        return None, [], "azure-storage-blob not installed. Run: pip install azure-storage-blob"

    conn_str       = credentials.get("connection_string", "").strip()
    account_name   = credentials.get("account_name", "").strip()
    account_key    = credentials.get("account_key", "").strip()
    container_name = credentials.get("container_name", "").strip()
    prefix         = credentials.get("prefix", "").strip()

    if not container_name:
        return None, [], "container_name is required for Azure Blob scanning."

    try:
        if conn_str:
            client = BlobServiceClient.from_connection_string(conn_str)
        elif account_name and account_key:
            from azure.storage.blob import BlobServiceClient as _BSC
            client = _BSC(
                account_url=f"https://{account_name}.blob.core.windows.net",
                credential=account_key,
            )
        else:
            return None, [], "Provide either connection_string or account_name + account_key."

        container = client.get_container_client(container_name)
        blobs     = list(container.list_blobs(name_starts_with=prefix or None))
        supported = [b for b in blobs if _is_supported(b.name)]

        if not supported:
            return None, [], None

        tmp_dir    = tempfile.mkdtemp(prefix="pii_azure_")
        downloaded = []

        for blob in supported[:max_files]:
            filename   = os.path.basename(blob.name) or blob.name.replace("/", "_")
            local_path = os.path.join(tmp_dir, filename)
            try:
                blob_client = container.get_blob_client(blob)
                with open(local_path, "wb") as out:
                    stream = blob_client.download_blob()
                    stream.readinto(out)
                downloaded.append({
                    "local": local_path,
                    "cloud": f"azure://{container_name}/{blob.name}",
                })
            except Exception:
                continue

        return tmp_dir, downloaded, None

    except Exception as e:
        return None, [], f"Azure Blob error: {e}"


# ══════════════════════════════════════════════════════
# Dropbox
# ══════════════════════════════════════════════════════

def scan_dropbox(credentials: dict, max_files: int = 100) -> tuple:
    """
    List and download supported files from Dropbox.

    credentials keys:
        access_token  — Dropbox OAuth2 long-lived or short-lived access token
        folder_path   — Dropbox folder path (default: "" = root)

    Returns: (tmp_dir: str, files: list[dict], error: str|None)
    """
    try:
        import dropbox as _dropbox
        from dropbox.exceptions import ApiError, AuthError
    except ImportError:
        return None, [], "dropbox SDK not installed. Run: pip install dropbox"

    access_token = credentials.get("access_token", "").strip()
    folder_path  = credentials.get("folder_path", "").strip()

    if not access_token:
        return None, [], "access_token is required for Dropbox scanning."

    # Normalise folder path
    if folder_path and not folder_path.startswith("/"):
        folder_path = "/" + folder_path
    if folder_path == "/":
        folder_path = ""

    try:
        dbx     = _dropbox.Dropbox(access_token)
        entries = []

        result = dbx.files_list_folder(folder_path, recursive=True)
        while True:
            for entry in result.entries:
                if hasattr(entry, "size") and _is_supported(entry.name):
                    entries.append(entry)
            if not result.has_more or len(entries) >= max_files:
                break
            result = dbx.files_list_folder_continue(result.cursor)

        if not entries:
            return None, [], None

        tmp_dir    = tempfile.mkdtemp(prefix="pii_dropbox_")
        downloaded = []

        for entry in entries[:max_files]:
            local_path = os.path.join(tmp_dir, entry.name)
            try:
                _, response = dbx.files_download(entry.path_lower)
                with open(local_path, "wb") as out:
                    out.write(response.content)
                downloaded.append({
                    "local": local_path,
                    "cloud": f"dropbox:/{entry.path_display}",
                })
            except (ApiError, Exception):
                continue

        return tmp_dir, downloaded, None

    except AuthError:
        return None, [], "Dropbox: invalid or expired access token."
    except Exception as e:
        return None, [], f"Dropbox error: {e}"


# ══════════════════════════════════════════════════════
# Dispatcher
# ══════════════════════════════════════════════════════

_PROVIDERS = {
    "s3"      : scan_s3,
    "gdrive"  : scan_gdrive,
    "azure"   : scan_azure,
    "dropbox" : scan_dropbox,
}


def scan_cloud(provider: str, credentials: dict, max_files: int = 100) -> tuple:
    """
    Dispatch to the correct cloud scanner.

    Returns: (tmp_dir: str | None, files: list[dict], error: str | None)
      - tmp_dir   : path to temp dir with downloaded files (caller must clean up)
      - files     : list of {"local": path, "cloud": cloud_url}
      - error     : error message if something failed, else None
    """
    scanner = _PROVIDERS.get(provider.lower().strip())
    if scanner is None:
        return None, [], f"Unknown provider '{provider}'. Supported: {', '.join(_PROVIDERS)}"
    return scanner(credentials, max_files=max_files)
