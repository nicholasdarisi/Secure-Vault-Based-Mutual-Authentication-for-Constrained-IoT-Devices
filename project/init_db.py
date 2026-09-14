import sqlite3
from pathlib import Path
from datetime import datetime

DB_PATH = "iot_auth.db"
SCHEMA_PATH = "schema.sql"

DEFAULT_DEVICE_ID = "ESP8266-01"
DEFAULT_VAULT = bytes([214, 249, 165, 110, 34, 247, 200, 70, 19, 83, 53, 38])

def now_str():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def main():
    if not Path(SCHEMA_PATH).exists():
        raise FileNotFoundError(f"File not found: {SCHEMA_PATH}")

    conn = sqlite3.connect(DB_PATH)
    try:
        with open(SCHEMA_PATH, "r", encoding="utf-8") as f:
            schema = f.read()

        conn.executescript(schema)

        ts = now_str()
        conn.execute(
            """
            INSERT INTO devices (
                device_id, vault, vault_version, n_keys, key_size_bytes,
                device_online, polling_interval_seconds, last_heartbeat_at,
                pending_command, created_at, updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                DEFAULT_DEVICE_ID,
                DEFAULT_VAULT,
                1,
                12,
                1,
                0,
                5,
                None,
                0,
                ts,
                ts,
            ),
        )

        conn.commit()
        print(f"Database successfully created: {DB_PATH}")
        print(f"Default initial device inserted: {DEFAULT_DEVICE_ID}")
    finally:
        conn.close()

if __name__ == "__main__":
    main()
