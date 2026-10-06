import sqlite3
import time
from pathlib import Path
from .crypto_utils import calculate_file_hash

DB_PATH = Path(__file__).resolve().parent.parent / "trusted_system.db"
FIRMWARE_V1_PATH = Path(__file__).resolve().parent.parent / "simulator" / "firmware_samples" / "firmware_v1.bin"


def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Initializes tables and seeds initial devices with verified Golden Measurements."""
    conn = get_db_connection()
    cursor = conn.cursor()

    # 1. Devices Table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS devices (
            device_id TEXT PRIMARY KEY,
            device_name TEXT NOT NULL,
            secret_key TEXT NOT NULL,
            golden_hash TEXT NOT NULL,
            trust_status TEXT NOT NULL DEFAULT 'UNTRUSTED',
            trust_token TEXT,
            token_expires_at REAL,
            last_attested_at REAL,
            created_at REAL NOT NULL
        )
    """)

    # 2. Challenge Nonces Table (Anti-Replay)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS challenges (
            nonce TEXT PRIMARY KEY,
            device_id TEXT NOT NULL,
            created_at REAL NOT NULL,
            expires_at REAL NOT NULL,
            is_used INTEGER NOT NULL DEFAULT 0
        )
    """)

    # 3. Attestation Audit Logs Table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS attestation_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id TEXT NOT NULL,
            timestamp REAL NOT NULL,
            nonce TEXT NOT NULL,
            reported_hash TEXT,
            expected_hash TEXT,
            trust_status TEXT NOT NULL,
            reason TEXT NOT NULL,
            is_allowed INTEGER NOT NULL
        )
    """)

    # 4. Telemetry Data Table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS telemetry_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id TEXT NOT NULL,
            payload TEXT NOT NULL,
            timestamp REAL NOT NULL,
            accepted INTEGER NOT NULL,
            rejection_reason TEXT
        )
    """)

    conn.commit()

    # Seed initial test devices if empty
    cursor.execute("SELECT COUNT(*) FROM devices")
    if cursor.fetchone()[0] == 0:
        # Calculate genuine firmware hash for device seeding
        golden_hash = "GENUINE_BASELINE_HASH_NOT_SET"
        if FIRMWARE_V1_PATH.exists():
            golden_hash = calculate_file_hash(FIRMWARE_V1_PATH)

        now = time.time()
        initial_devices = [
            ("IOT-DEV-101", "Smart Energy Meter A", "SECRET_KEY_101_SECURE", golden_hash, "UNTRUSTED", None, None, None, now),
            ("IOT-DEV-102", "Factory Temperature Sensor B", "SECRET_KEY_102_SECURE", golden_hash, "UNTRUSTED", None, None, None, now),
            ("IOT-DEV-103", "CCTV Camera C", "SECRET_KEY_103_SECURE", golden_hash, "UNTRUSTED", None, None, None, now),
        ]
        cursor.executemany("""
            INSERT INTO devices (
                device_id, device_name, secret_key, golden_hash,
                trust_status, trust_token, token_expires_at, last_attested_at, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, initial_devices)
        conn.commit()

    conn.close()
