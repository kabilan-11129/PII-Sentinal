"""
db_store.py — Data storage and retrieval module for PII Sentinel.
Inserts detected PII records into MySQL and fetches them for the dashboard.
"""

from datetime import date
from database.db_connection import get_db_connection


# ── PII category → data_type mapping ──
# SPII = Sensitive PII (biometric, aadhaar, financial, health)
SPII_CATEGORIES = {"Aadhaar", "PAN", "Card", "BankAccount", "HealthData", "Passport"}


def _classify_data_type(data_category: str) -> str:
    """Return 'SPII' for sensitive identifiers, 'PII' for the rest."""
    return "SPII" if data_category in SPII_CATEGORIES else "PII"


# ──────────────────────────────────────────────
# Insert a single detected PII record
# ──────────────────────────────────────────────
def insert_record(user_id: str, data_type: str, data_category: str, data_value: str) -> bool:
    """
    Insert a detected PII value into personal_data_records.
    uploaded_at is automatically set to today's date.
    Returns True on success, False on failure.
    """
    conn = None
    try:
        conn = get_db_connection()
        if conn is None:
            return False

        cursor = conn.cursor()
        query = """
            INSERT INTO personal_data_records
                (user_id, data_type, data_category, data_value, uploaded_at)
            VALUES (%s, %s, %s, %s, %s)
        """
        cursor.execute(query, (user_id, data_type, data_category, data_value, date.today()))
        conn.commit()
        cursor.close()
        return True
    except Exception as e:
        print(f"[DB] insert_record error: {e}")
        return False
    finally:
        if conn and conn.is_connected():
            conn.close()


# ──────────────────────────────────────────────
# Bulk insert — stores all PII detected in a scan
# ──────────────────────────────────────────────
def insert_detected_pii(pii_results: dict, source_id: str = "AUTO") -> int:
    """
    Given a pii_results dict from detect_all_pii(), insert each
    detected value into the database.

    Args:
        pii_results: { "Email": [...], "Phone": [...], ... }
        source_id:   identifier for the scan source (file name, user ID, etc.)

    Returns:
        Number of records successfully inserted.
    """
    inserted = 0
    conn = None
    try:
        conn = get_db_connection()
        if conn is None:
            return 0

        cursor = conn.cursor()
        query = """
            INSERT INTO personal_data_records
                (user_id, data_type, data_category, data_value, uploaded_at)
            VALUES (%s, %s, %s, %s, %s)
        """
        today = date.today()

        for category, values in pii_results.items():
            if not values:
                continue
            data_type = _classify_data_type(category)
            for value in values:
                try:
                    cursor.execute(query, (source_id, data_type, category, str(value), today))
                    inserted += 1
                except Exception as row_err:
                    print(f"[DB] Row insert error ({category}): {row_err}")

        conn.commit()
        cursor.close()
    except Exception as e:
        print(f"[DB] insert_detected_pii error: {e}")
    finally:
        if conn and conn.is_connected():
            conn.close()

    return inserted


# ──────────────────────────────────────────────
# Fetch all records
# ──────────────────────────────────────────────
def get_all_records() -> list:
    """
    Return all rows from personal_data_records as a list of dicts.
    Uses cursor(dictionary=True) for easy JSON serialisation.
    Returns an empty list if the database is unavailable.
    """
    conn = None
    try:
        conn = get_db_connection()
        if conn is None:
            return []

        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM personal_data_records ORDER BY record_id DESC")
        rows = cursor.fetchall()
        cursor.close()

        # Convert date/datetime objects to ISO strings for JSON
        for row in rows:
            for key, val in row.items():
                if hasattr(val, "isoformat"):
                    row[key] = val.isoformat()

        return rows
    except Exception as e:
        print(f"[DB] get_all_records error: {e}")
        return []
    finally:
        if conn and conn.is_connected():
            conn.close()


# ──────────────────────────────────────────────
# Fetch records filtered by data_type
# ──────────────────────────────────────────────
def get_records_by_type(data_type: str) -> list:
    """Return records filtered by data_type ('PII' or 'SPII')."""
    conn = None
    try:
        conn = get_db_connection()
        if conn is None:
            return []

        cursor = conn.cursor(dictionary=True)
        cursor.execute(
            "SELECT * FROM personal_data_records WHERE data_type = %s ORDER BY record_id DESC",
            (data_type,),
        )
        rows = cursor.fetchall()
        cursor.close()

        for row in rows:
            for key, val in row.items():
                if hasattr(val, "isoformat"):
                    row[key] = val.isoformat()

        return rows
    except Exception as e:
        print(f"[DB] get_records_by_type error: {e}")
        return []
    finally:
        if conn and conn.is_connected():
            conn.close()


# ──────────────────────────────────────────────
# Fetch records older than retention period
# ──────────────────────────────────────────────
def get_expired_records(retention_years: int = 3) -> list:
    """Return records whose uploaded_at is older than retention_years."""
    conn = None
    try:
        conn = get_db_connection()
        if conn is None:
            return []

        cursor = conn.cursor(dictionary=True)
        cursor.execute(
            "SELECT * FROM personal_data_records WHERE uploaded_at < DATE_SUB(CURDATE(), INTERVAL %s YEAR)",
            (retention_years,),
        )
        rows = cursor.fetchall()
        cursor.close()

        for row in rows:
            for key, val in row.items():
                if hasattr(val, "isoformat"):
                    row[key] = val.isoformat()

        return rows
    except Exception as e:
        print(f"[DB] get_expired_records error: {e}")
        return []
    finally:
        if conn and conn.is_connected():
            conn.close()
