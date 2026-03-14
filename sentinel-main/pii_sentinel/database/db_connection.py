"""
MySQL database connection module for PII Sentinel.
Connects to the 'db' database containing personal_data_records.
"""

import mysql.connector
from mysql.connector import Error

DB_CONFIG = {
    "host": "localhost",
    "user": "root",
    "password": "123456",
    "database": "db"
}


def get_db_connection():
    """
    Create and return a MySQL database connection.
    Returns None if connection fails.
    """
    try:
        connection = mysql.connector.connect(**DB_CONFIG)
        if connection.is_connected():
            return connection
    except Error as e:
        print(f"[DB] MySQL connection error: {e}")
    return None
