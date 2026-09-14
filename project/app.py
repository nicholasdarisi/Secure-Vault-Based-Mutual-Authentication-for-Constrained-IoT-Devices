"""
IoT Authentication Server

This Flask application implements a secure authentication protocol for IoT devices using a vault-based key management system.
The protocol enables mutual authentication between devices and server through a challenge-response mechanism,
with cryptographic operations ensuring confidentiality and integrity.

Key components:
- Admin dashboard for monitoring and control
- Device heartbeat and pending command management
- Multi-phase authentication protocol (M1-M4) with vault updates
- Sensor data collection post-authentication
- Rate limiting and session management for security

The vault system uses XOR-based key derivation and HMAC for secure updates after successful authentication.
"""

from __future__ import annotations

import base64
import threading
import hashlib
import hmac
import json
import os
import sqlite3
import time
from datetime import datetime, timedelta
from typing import Any

from flask import Flask, jsonify, render_template, request, session, redirect, url_for

try:
    from Crypto.Cipher import AES
except ImportError as exc:  # pragma: no cover
    raise SystemExit(
        "pycryptodome is missing. Install it with: pip install flask pycryptodome"
    ) from exc

DB_PATH = "iot_auth.db" #db path
SESSION_TIMEOUT_SECONDS = 300
DEFAULT_DEVICE_ID = "ESP8266-01" 
DEFAULT_POLLING_SECONDS = 5 #time between pings of the device
RATE_LIMIT_WINDOW_SECONDS = 60 #time window for rate limiting in seconds
RATE_LIMIT_AUTH_START_MAX = 10 #max auth start attempts per device per window
RATE_LIMIT_AUTH_RESPOND_MAX = 15 #max auth respond attempts per device per window

# Initialize Flask app with configuration
app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "dev-secret-key-change-me")

#credentials
ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "demo123")

# Global session context for active authentication sessions
# Stores temporary state during protocol execution
SESSION_CTX: dict[str, dict[str, Any]] = {} 
# Rate limiting storage: maps bucket keys to lists of timestamps
RATE_LIMIT_STORE: dict[str, list[float]] = {} 
# Thread lock to synchronize access to SESSION_CTX across requests
SESSION_CTX_LOCK = threading.Lock() 

def is_admin_logged_in() -> bool:
    return session.get("is_admin") is True


def require_admin():
    """
    Middleware to enforce admin authentication for protected routes.
    Redirects to login page for HTML requests or returns 401 for API calls.
    """
    if is_admin_logged_in():
        return None

    wants_json = (
        request.path.startswith("/ui/")
        or request.headers.get("X-Requested-With") == "XMLHttpRequest"
        or "application/json" in request.headers.get("Accept", "")
    )

    if wants_json:
        return jsonify({"ok": False, "error": "Unauthorized access"}), 401

    return redirect(url_for("admin_login"))


# ====
# Utility generali
# ====

def utcnow_str() -> str:
    """Get current UTC time as formatted string for database storage."""
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def now_ts() -> float:
    """Get current timestamp as float for session timeout calculations."""
    return time.time()

def check_rate_limit(bucket: str, max_requests: int):
    """
    Rate limiting mechanism to prevent abuse.
    Tracks requests per IP address within a time window.
    Used to protect authentication endpoints from brute force attacks.
    """
    current_time = now_ts()
    key = f"{bucket}:{request.remote_addr}"

    timestamps = RATE_LIMIT_STORE.get(key, [])
    timestamps = [ts for ts in timestamps if current_time - ts < RATE_LIMIT_WINDOW_SECONDS]

    if len(timestamps) >= max_requests:
        return jsonify({
            "ok": False,
            "error": "Too many requests. Please retry later."
        }), 429

    timestamps.append(current_time)
    RATE_LIMIT_STORE[key] = timestamps
    return None

def has_active_session_for_device(device_id: str) -> bool:
    """
    Check if a device already has an active authentication session.
    Prevents multiple concurrent authentications for the same device.
    """
    cleanup_expired_sessions()

    for ctx in SESSION_CTX.values():
        if ctx.get("device_id") == device_id:
            return True

    return False


def b64e(data: bytes) -> str:
    """Base64 encode bytes to string for JSON serialization."""
    return base64.b64encode(data).decode("utf-8")


def b64d(data: str) -> bytes:
    """Base64 decode string to bytes for cryptographic operations."""
    return base64.b64decode(data.encode("utf-8"))


def json_dumps(value: Any) -> str:
    """JSON serialize with consistent formatting for cryptographic integrity."""
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def get_db() -> sqlite3.Connection:
    """Get database connection with foreign key enforcement."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def pad_pkcs7(data: bytes, block_size: int = 16) -> bytes:
    """PKCS7 padding for AES block cipher alignment."""
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len]) * pad_len


def unpad_pkcs7(data: bytes, block_size: int = 16) -> bytes:
    """Remove PKCS7 padding, validating integrity."""
    if not data or len(data) % block_size != 0:
        raise ValueError("Cryptographic error")
    pad_len = data[-1]
    if pad_len < 1 or pad_len > block_size:
        raise ValueError("Cryptographic error")
    if data[-pad_len:] != bytes([pad_len]) * pad_len:
        raise ValueError("Cryptographic error")
    return data[:-pad_len]


def aes_encrypt(key: bytes, plaintext: bytes) -> bytes:
    """AES-CBC encryption with random IV prepended."""
    if len(key) != 16:
        raise ValueError("Cryptographic error")
    iv = os.urandom(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad_pkcs7(plaintext))
    return iv + ciphertext


def aes_decrypt(key: bytes, ciphertext: bytes) -> bytes:
    """AES-CBC decryption with IV extraction and padding removal."""
    if len(key) != 16:
        raise ValueError("Cryptographic error")
    if len(ciphertext) < 32 or len(ciphertext) % 16 != 0:
        raise ValueError("Cryptographic error")
    iv, body = ciphertext[:16], ciphertext[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(body)
    return unpad_pkcs7(plaintext)


def xor_bytes(a: bytes, b: bytes) -> bytes:
    """XOR two byte sequences of equal length."""
    if len(a) != len(b):
        raise ValueError("The sequences to be xorted must have the same length")
    return bytes(x ^ y for x, y in zip(a, b))


def xor_many(items: list[bytes]) -> bytes:
    """XOR multiple byte sequences together (associative operation)."""
    if not items:
        raise ValueError("The list of keys cannot be empty")
    result = items[0]
    for item in items[1:]:
        result = xor_bytes(result, item)
    return result

def compute_message_hmac(key: bytes, message: bytes) -> str:
    """Compute HMAC-SHA256 for message integrity verification."""
    return hmac.new(key, message, hashlib.sha256).hexdigest()


def split_vault(vault_blob: bytes, key_size_bytes: int) -> list[bytes]:
    """Split vault into individual key segments."""
    return [vault_blob[i:i + key_size_bytes] for i in range(0, len(vault_blob), key_size_bytes)]


def compute_k_from_indices(vault_blob: bytes, key_size_bytes: int, indices: list[int]) -> bytes:
    """Derive cryptographic key by XORing selected vault segments."""
    keys = split_vault(vault_blob, key_size_bytes)
    selected = [keys[i] for i in indices]
    return xor_many(selected)


def update_vault(current_vault: bytes, transcript_bytes: bytes) -> bytes:
    """Update vault using HMAC-based key derivation for forward secrecy."""
    digest = hmac.new(transcript_bytes, current_vault, hashlib.sha256).digest()
    new_vault = bytearray(current_vault)
    block_len = len(digest)
    for start in range(0, len(new_vault), block_len):
        chunk = new_vault[start:start + block_len]
        for i in range(len(chunk)):
            chunk[i] ^= digest[i]
        new_vault[start:start + block_len] = chunk
    return bytes(new_vault)


def cleanup_expired_sessions() -> None:
    """Remove expired sessions from memory to prevent memory leaks."""
    expired = []
    for session_id, ctx in SESSION_CTX.items():
        if now_ts() - ctx.get("created_ts", 0) > SESSION_TIMEOUT_SECONDS:
            expired.append(session_id)
    for session_id in expired:
        SESSION_CTX.pop(session_id, None)


def build_transcript(session_id: str, c1: list[int], r1: bytes, t1: bytes, c2: list[int], r2: bytes, t2: bytes) -> bytes:
    """
    Build authentication transcript for vault update.
    Contains all exchanged values to ensure both parties agree on the session.
    """
    transcript_obj = {
        "session_id": session_id,
        "C1": c1,
        "r1": b64e(r1),
        "t1": b64e(t1),
        "C2": c2,
        "r2": b64e(r2),
        "t2": b64e(t2),
    }
    return json_dumps(transcript_obj).encode("utf-8")


def safe_int_bool(value: Any) -> bool:
    """Safely convert database integer to boolean."""
    return bool(int(value)) if value is not None else False


def format_seconds_ago(dt_str: str | None) -> int | None:
    """Convert datetime string to seconds since now for UI display."""
    if not dt_str:
        return None
    try:
        ts = datetime.strptime(dt_str, "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return None
    return max(0, int((datetime.now() - ts).total_seconds()))


def derive_aes_key(material: bytes) -> bytes:
    """Derive 128-bit AES key from arbitrary material using SHA256."""
    return hashlib.sha256(material).digest()[:16]

# ====
# Accesso DB e logging
# ====

def log_event(level: str, text: str, device_id: str | None = None, session_id: str | None = None) -> None:
    """Log events to database for audit trail and debugging."""
    conn = get_db()
    conn.execute(
        "INSERT INTO logs(device_id, session_id, level, text, created_at) VALUES (?, ?, ?, ?, ?)",
        (device_id, session_id, level, text, utcnow_str()),
    )
    conn.commit()
    conn.close()


def get_device(device_id: str) -> sqlite3.Row | None:
    """Retrieve device configuration from database."""
    conn = get_db()
    row = conn.execute("SELECT * FROM devices WHERE device_id = ?", (device_id,)).fetchone()
    conn.close()
    return row


def set_device_pending(device_id: str, pending: bool) -> None:
    """Set pending command flag for device to trigger authentication."""
    conn = get_db()
    conn.execute(
        "UPDATE devices SET pending_command = ?, updated_at = ? WHERE device_id = ?",
        (1 if pending else 0, utcnow_str(), device_id),
    )
    conn.commit()
    conn.close()


def update_device_heartbeat(device_id: str, polling_interval_seconds: int | None = None) -> None:
    """Update device online status and heartbeat timestamp."""
    conn = get_db()
    conn.execute(
        """
        UPDATE devices
        SET device_online = 1,
            polling_interval_seconds = COALESCE(?, polling_interval_seconds),
            last_heartbeat_at = ?,
            updated_at = ?
        WHERE device_id = ?
        """,
        (polling_interval_seconds, utcnow_str(), utcnow_str(), device_id),
    )
    conn.commit()
    conn.close()


def create_session(session_id: str, device_id: str) -> None:
    """Initialize new authentication session in database."""
    conn = get_db()
    conn.execute(
        """
        INSERT OR REPLACE INTO sessions(
            session_id, device_id, status, protocol_phase,
            session_key_generated, auth_device_status, auth_server_status,
            vault_status, started_at
        ) VALUES (?, ?, 'pending', 'm1_sent', 0, 'pending', 'pending', 'unchanged', ?)
        """,
        (session_id, device_id, utcnow_str()),
    )
    conn.commit()
    conn.close()


# FIX: Whitelist colonne per prevenire SQL injection dinamica
ALLOWED_SESSION_COLUMNS = {
    "status", "protocol_phase", "session_key_generated",
    "auth_device_status", "auth_server_status", "vault_status",
    "r1", "t1", "r2", "t2", "completed_at",
}

def update_session(session_id: str, **fields: Any) -> None:
    """
    Update session fields in database with SQL injection protection.
    Only allows whitelisted columns to prevent security vulnerabilities.
    """
    if not fields:
        return
    columns = []
    values = []
    for key, value in fields.items():
        if key not in ALLOWED_SESSION_COLUMNS:
            continue  #ignore unauthorized columns
        columns.append(f"{key} = ?")
        values.append(value)
    if not columns:
        return
    values.append(session_id)
    sql = f"UPDATE sessions SET {', '.join(columns)} WHERE session_id = ?"    
    conn = get_db()
    conn.execute(sql, values)
    conn.commit()
    conn.close()


def reset_runtime_and_protocol_state() -> None:
    """
    Reset all runtime state for testing/debugging.
    Clears sessions, logs, sensor data, and resets device states.
    """
    SESSION_CTX.clear()

    conn = get_db()
    try:
        conn.execute("DELETE FROM protocol_messages")
        conn.execute("DELETE FROM logs")
        conn.execute("DELETE FROM sensor_data")
        conn.execute("DELETE FROM sessions")

        conn.execute(
            """
            UPDATE devices
            SET pending_command = 0,
                device_online = 0,
                updated_at = ?
            """,
            (utcnow_str(),),
        )

        conn.commit()
    finally:
        conn.close()


def insert_protocol_message(
    session_id: str,
    message_type: str,
    direction: str,
    status: str,
    percent: int,
    title: str,
    subtitle: str,
    detail: str,
    payload_preview: str | None = None,
) -> None:
    """Insert protocol message for UI timeline tracking."""
    conn = get_db()
    conn.execute(
        """
        INSERT INTO protocol_messages(
            session_id, message_type, direction, status, percent,
            title, subtitle, detail, payload_preview, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            session_id,
            message_type,
            direction,
            status,
            percent,
            title,
            subtitle,
            detail,
            payload_preview,
            utcnow_str(),
        ),
    )
    conn.commit()
    conn.close()


def update_protocol_message(session_id: str, message_type: str, status: str, percent: int, detail: str) -> None:
    """Update existing protocol message status for timeline progression."""
    conn = get_db()
    conn.execute(
        """
        UPDATE protocol_messages
        SET status = ?, percent = ?, detail = ?
        WHERE id = (
            SELECT id FROM protocol_messages
            WHERE session_id = ? AND message_type = ?
            ORDER BY id DESC LIMIT 1
        )
        """,
        (status, percent, detail, session_id, message_type),
    )
    conn.commit()
    conn.close()


def get_latest_device() -> sqlite3.Row | None:
    """Get most recently updated device for dashboard display."""
    conn = get_db()
    row = conn.execute("SELECT * FROM devices ORDER BY updated_at DESC, created_at DESC LIMIT 1").fetchone()
    conn.close()
    return row


def get_latest_session(device_id: str | None) -> sqlite3.Row | None:
    """Get most recent session for a device."""
    if not device_id:
        return None
    conn = get_db()
    row = conn.execute(
        "SELECT * FROM sessions WHERE device_id = ? ORDER BY started_at DESC LIMIT 1",
        (device_id,),
    ).fetchone()
    conn.close()
    return row


def get_session_by_id(session_id: str) -> sqlite3.Row | None:
    """Retrieve session by ID for validation."""
    conn = get_db()
    row = conn.execute(
        "SELECT * FROM sessions WHERE session_id = ?",
        (session_id,),
    ).fetchone()
    conn.close()
    return row


def get_session_messages(session_id: str | None) -> list[sqlite3.Row]:
    """Get all protocol messages for session timeline."""
    if not session_id:
        return []
    conn = get_db()
    rows = conn.execute(
        "SELECT * FROM protocol_messages WHERE session_id = ? ORDER BY id ASC",
        (session_id,),
    ).fetchall()
    conn.close()
    return rows


def get_recent_logs(limit: int = 50) -> list[sqlite3.Row]:
    """Get recent log entries for dashboard display."""
    conn = get_db()
    rows = conn.execute(
        "SELECT * FROM logs ORDER BY id DESC LIMIT ?",
        (limit,),
    ).fetchall()
    conn.close()
    return rows


def get_latest_sensor_row(device_id: str | None) -> sqlite3.Row | None:
    """Get most recent sensor data for device."""
    if not device_id:
        return None
    conn = get_db()
    row = conn.execute(
        "SELECT * FROM sensor_data WHERE device_id = ? ORDER BY id DESC LIMIT 1",
        (device_id,),
    ).fetchone()
    conn.close()
    return row


def get_sensor_history(device_id: str | None, limit: int = 10) -> list[sqlite3.Row]:
    """Get sensor data history for charts (chronological order)."""
    if not device_id:
        return []
    conn = get_db()
    rows = conn.execute(
        "SELECT * FROM sensor_data WHERE device_id = ? ORDER BY id DESC LIMIT ?",
        (device_id, limit),
    ).fetchall()
    conn.close()
    return list(reversed(rows))


# ====
# Dashboard e UI
# ====

def default_timeline() -> list[dict[str, Any]]:
    """
    Default protocol timeline structure for UI display.
    Shows the 5 phases of the authentication protocol.
    """
    return [
        {
            "key": "M1",
            "title": "M1 — Device -> Server",
            "subtitle": "DeviceID || SessionID",
            "status": "waiting",
            "percent": 0,
            "detail": "The device will send the initial message when it receives the boot command.",
        },
        {
            "key": "M2",
            "title": "M2 — Server -> Device",
            "subtitle": "{C1, r1}",
            "status": "waiting",
            "percent": 0,
            "detail": "The server generates the challenge and the nonce r1 after receiving M1.",
        },
        {
            "key": "M3",
            "title": "M3 — Device -> Server",
            "subtitle": "Enc(k1, r1 || t1 || {C2, r2})",
            "status": "waiting",
            "percent": 0,
            "detail": "The device responds to the server's challenge and proposes its own challenge C2.",
        },
        {
            "key": "M4",
            "title": "M4 — Server -> Device",
            "subtitle": "Enc(k2 XOR t1, r2 || t2)",
            "status": "waiting",
            "percent": 0,
            "detail": "The server completes the mutual authentication by responding to the device.",
        },
        {
            "key": "vault_update",
            "title": "Update Vault",
            "subtitle": "HMAC(current_vault, exchanged_data)",
            "status": "waiting",
            "percent": 0,
            "detail": "The vault is updated in a synchronized manner at the end of the session.",
        },
    ]

@app.route("/admin/login", methods=["GET", "POST"])
def admin_login() -> Any:
    """
    Admin authentication endpoint.
    Serves login form and handles authentication.
    Uses environment variables for credentials.
    """
    error_html = ""
    status_code = 200

    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
            session["is_admin"] = True
            session["admin_username"] = username
            log_event("INFO", "Admin login successful.")
            return redirect(url_for("home"))

        log_event("WARNING", f"Admin login attempt failed for username='{username}'.")
        error_html = '<div class="modal-error" style="display:block;"> Invalid credentials. Please try again.</div>'
        status_code = 401

    return f"""<!DOCTYPE html>
    <html lang="it">
    <head>
      <meta charset="UTF-8"/>
      <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
      <title>IoT Auth — Admin Login</title>
      <style>
        :root {{
          --bg: #020617;
          --cyan: #22d3ee;
          --muted: #94a3b8;
          --rose: #fb7185;
          --line: rgba(255,255,255,0.08);
        }}
        *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
          min-height: 100vh;
          display: flex;
          align-items: center;
          justify-content: center;
          font-family: Inter, ui-sans-serif, system-ui, -apple-system, "Segoe UI", sans-serif;
          background:
            radial-gradient(circle at top left, rgba(34,211,238,0.08), transparent 26%),
            radial-gradient(circle at top right, rgba(167,139,250,0.08), transparent 28%),
            linear-gradient(180deg, #020617 0%, #0f172a 100%);
          color: #e5eefc;
        }}
        .modal-overlay {{
          position: fixed;
          inset: 0;
          background: rgba(0,0,0,0.65);
          backdrop-filter: blur(6px);
          display: flex;
          justify-content: center;
          align-items: center;
        }}
        .modal-box {{
          background: #0f172a;
          border: 1px solid rgba(255,255,255,0.12);
          border-radius: 24px;
          padding: 28px 32px;
          max-width: 420px;
          width: 90%;
          box-shadow: 0 32px 80px rgba(0,0,0,0.6);
          text-align: center;
        }}
        .modal-box .eyebrow {{
          display: inline-flex;
          align-items: center;
          gap: 8px;
          padding: 6px 14px;
          border-radius: 999px;
          border: 1px solid rgba(34,211,238,0.2);
          background: rgba(34,211,238,0.09);
          color: #b6f3fb;
          text-transform: uppercase;
          letter-spacing: 0.18em;
          font-size: 11px;
          font-weight: 700;
          margin-bottom: 16px;
        }}
        .modal-box h3 {{
          margin: 0 0 8px;
          font-size: 22px;
          font-weight: 700;
        }}
        .modal-box p {{
          color: var(--muted);
          font-size: 14px;
          line-height: 1.6;
          margin: 0 0 20px;
        }}
        .modal-error {{
          color: var(--rose);
          font-size: 13px;
          margin-bottom: 12px;
          display: none;
        }}
        .field-label {{
          display: block;
          text-align: left;
          font-size: 11px;
          text-transform: uppercase;
          letter-spacing: 0.16em;
          color: var(--muted);
          margin-bottom: 6px;
          font-weight: 700;
        }}
        .modal-box input {{
          width: 100%;
          padding: 12px 16px;
          border-radius: 14px;
          border: 1px solid rgba(255,255,255,0.15);
          background: rgba(2,6,23,0.6);
          color: white;
          font-size: 15px;
          margin-bottom: 16px;
          outline: none;
          transition: border-color 0.2s;
          font-family: inherit;
        }}
        .modal-box input:focus {{
          border-color: var(--cyan);
        }}
        .modal-buttons {{
          display: flex;
          gap: 12px;
          justify-content: center;
          margin-top: 4px;
        }}
        .btn-primary {{
          background: linear-gradient(135deg, #22d3ee, #60a5fa);
          color: #06202a;
          border: 0;
          border-radius: 16px;
          padding: 14px 28px;
          font-size: 14px;
          font-weight: 700;
          cursor: pointer;
          transition: 0.22s ease;
          font-family: inherit;
        }}
        .btn-primary:hover {{ transform: translateY(-1px); opacity: 0.92; }}
      </style>
    </head>
    <body>
      <div class="modal-overlay">
        <div class="modal-box">
          <div class="eyebrow"> Secure Vault Auth</div>
          <h3>Administrator Access</h3>
          <p>Enter your admin credentials to access the dashboard.</p>
          {error_html}
          <form method="post" autocomplete="off">
            <label class="field-label" for="username">Username</label>
            <input type="text" id="username" name="username" placeholder="" autofocus />
            <label class="field-label" for="password">Password</label>
            <input type="password" id="password" name="password" placeholder="" />
            <div class="modal-buttons">
              <button type="submit" class="btn-primary">Access</button>
            </div>
          </form>
        </div>
      </div>
    </body>
    </html>""", status_code

@app.route("/admin/logout")
def admin_logout() -> Any:
    """Clear admin session and redirect to login."""
    username = session.get("admin_username", "unknown")
    session.clear()
    log_event("INFO", f"Admin logout performed by username='{username}'.")
    return redirect(url_for("admin_login"))

@app.route("/")
def home() -> Any:
    """Serve main dashboard page, requires admin authentication."""
    admin_check = require_admin()
    if admin_check:
        return admin_check
    return render_template("dashboard.html")


@app.route("/ui/dashboard")
def ui_dashboard() -> Any:
    """
    API endpoint providing dashboard data.
    Aggregates device status, session info, logs, sensor data, and protocol timeline.
    Sanitizes logs to prevent information leakage.
    """
    admin_check = require_admin()
    if admin_check:
        return admin_check
    cleanup_expired_sessions()

    device = get_latest_device()
    device_id = device["device_id"] if device else None
    session = get_latest_session(device_id)
    session_id = session["session_id"] if session else None

    messages = get_session_messages(session_id)
    timeline = default_timeline()
    if messages:
        by_type = {row["message_type"]: row for row in messages}
        for item in timeline:
            row = by_type.get(item["key"])
            if row:
                item.update(
                    {
                        "status": row["status"],
                        "percent": row["percent"],
                        "detail": row["detail"] or item["detail"],
                    }
                )

    # FIX: Log sanitizzati — solo livello e timestamp, nessun dettaglio interno
    logs = [
        {
            "timestamp": row["created_at"],
            "level": row["level"],
            "text": row["text"] if row["level"] in ("INFO", "READY", "PING") else "Event recorded.",
        }
        for row in reversed(get_recent_logs())
    ]

    latest_sensor = get_latest_sensor_row(device_id)
    sensor_history_rows = get_sensor_history(device_id)
    sensor_data = {
        "temperature": latest_sensor["temperature"] if latest_sensor else None,
        "humidity": latest_sensor["humidity"] if latest_sensor else None,
        "battery": latest_sensor["battery"] if latest_sensor else None,
        "last_sent_at": latest_sensor["created_at"] if latest_sensor else None,
        "last_payload": json.loads(latest_sensor["payload_json"]) if latest_sensor and latest_sensor["payload_json"] else None,
        "history": [
            {
                "timestamp": row["created_at"],
                "temperature": row["temperature"],
                "humidity": row["humidity"],
                "battery": row["battery"],
            }
            for row in sensor_history_rows
        ],
    }

    # FIX: Rimosso vault_hash dalla risposta e rimosso print()
    last_heartbeat_seconds_ago = format_seconds_ago(device["last_heartbeat_at"]) if device else None
    DEVICE_TIMEOUT = 10
    device_online = False
    if last_heartbeat_seconds_ago is not None:
        device_online = last_heartbeat_seconds_ago <= DEVICE_TIMEOUT

    status = {
        "server_online": True,
        "database_online": True,
        "device_id": device_id or "—",
        "session_id": session_id or "—",
        "polling_interval_seconds": device["polling_interval_seconds"] if device else DEFAULT_POLLING_SECONDS,
        "pending_command": safe_int_bool(device["pending_command"]) if device else False,
        "protocol_phase": session["protocol_phase"] if session else "idle",
        "auth_device_status": session["auth_device_status"] if session else "pending",
        "auth_server_status": session["auth_server_status"] if session else "pending",
        "session_key_generated": safe_int_bool(session["session_key_generated"]) if session else False,
        "vault_status": session["vault_status"] if session else "unchanged",
        "vault_version": device["vault_version"] if device else None,
        "last_auth_result": session["status"] if session else "none",
        "session_completed_at": session["completed_at"] if session else None,
        "session_timeout_seconds": 60,
        "last_heartbeat_seconds_ago": last_heartbeat_seconds_ago,
        "device_online": device_online,
    }

    metrics = {
        "backend_name": "Flask API",
        "database_name": "SQLite .db",
        "transport_protocol": "HTTP/JSON",
    }

    return jsonify(
        {
            "status": status,
            "metrics": metrics,
            "timeline": timeline,
            "logs": logs,
            "sensor_data": sensor_data,
        }
    )


@app.route("/ui/start-demo", methods=["POST"])
def ui_start_demo() -> Any:
    """Trigger authentication start for a device from dashboard."""
    admin_check = require_admin()
    if admin_check:
        return admin_check

    device_id = (request.get_json(silent=True) or {}).get("device_id", DEFAULT_DEVICE_ID)
    device = get_device(device_id)
    if not device:
        return jsonify({"ok": False, "error": f"Device {device_id} not found in database"}), 404

    set_device_pending(device_id, True)
    log_event("READY", "start_auth command set from dashboard.", device_id=device_id)
    return jsonify({"ok": True, "device_id": device_id})


@app.route("/ui/reset", methods=["POST"])
def ui_reset() -> Any:
    """Reset all protocol state for testing."""
    admin_check = require_admin()
    if admin_check:
        return admin_check

    reset_runtime_and_protocol_state()
    log_event("INFO", "Protocol state reset from dashboard.")
    return jsonify({"ok": True})


# ====
# Endpoint device
# ====

@app.route("/device/heartbeat", methods=["POST"])
def device_heartbeat() -> Any:
    """Device heartbeat endpoint to report online status and update polling interval."""
    body = request.get_json(force=True)
    device_id = body.get("device_id")
    polling = body.get("polling_interval_seconds", DEFAULT_POLLING_SECONDS)
    if not device_id:
        return jsonify({"ok": False, "error": "device_id missing"}), 400
    if not get_device(device_id):
        return jsonify({"ok": False, "error": f"Device {device_id} not registered"}), 404
    update_device_heartbeat(device_id, int(polling))
    log_event("PING", "Heartbeat received from device.", device_id=device_id)
    return jsonify({"ok": True, "server_time": utcnow_str()})


@app.route("/device/pending", methods=["GET"])
def device_pending() -> Any:
    """Check if device has pending authentication command."""
    device_id = request.args.get("device_id", DEFAULT_DEVICE_ID)
    device = get_device(device_id)
    if not device:
        return jsonify({"ok": False, "error": f"Device {device_id} not registered"}), 404
    return jsonify(
        {
            "ok": True,
            "device_id": device_id,
            "start_auth": safe_int_bool(device["pending_command"]),
            "polling_interval_seconds": device["polling_interval_seconds"] or DEFAULT_POLLING_SECONDS,
        }
    )


# ====
# Protocollo di autenticazione
# ====
@app.route("/auth/start", methods=["POST"])
def auth_start() -> Any:
    """
    M1: Device initiates authentication.
    Server generates challenge C1 and nonce r1, stores session context.
    This begins the mutual authentication protocol.
    """
    rate_limit_response = check_rate_limit("auth_start", RATE_LIMIT_AUTH_START_MAX)
    if rate_limit_response:
        return rate_limit_response

    body = request.get_json(force=True)
    device_id = body.get("device_id")
    session_id = body.get("session_id")

    if not device_id or not session_id:
        return jsonify({"ok": False, "error": "device_id and session_id are required"}), 400

    device = get_device(device_id)
    if not device:
        return jsonify({"ok": False, "error": f"Device {device_id} not registered"}), 404

    n_keys = int(device["n_keys"])
    key_size_bytes = int(device["key_size_bytes"])
    p = min(3, n_keys)

    c1 = sorted(set(os.urandom(p)))
    while len(c1) < p:
        c1 = sorted(set(os.urandom(p)))
    c1 = [x % n_keys for x in c1][:p]
    while len(set(c1)) < p:
        c1 = [(v + i + 1) % n_keys for i, v in enumerate(c1)]
        c1 = list(dict.fromkeys(c1))[:p]
        while len(c1) < p:
            c1.append((c1[-1] + 1) % n_keys)

    r1 = os.urandom(key_size_bytes)

    with SESSION_CTX_LOCK:
        cleanup_expired_sessions()

        for ctx in SESSION_CTX.values():
            if ctx.get("device_id") == device_id and ctx.get("auth_in_progress") is True:
                return jsonify({
                    "ok": False,
                    "error": "A session is already in progress for this device"
                }), 409

        SESSION_CTX[session_id] = {
            "device_id": device_id,
            "c1": c1,
            "r1": r1,
            "created_ts": now_ts(),
            "auth_in_progress": True,
        }

    create_session(session_id, device_id)
    update_session(session_id, protocol_phase="m2_sent")
    insert_protocol_message(
        session_id,
        "M1",
        "device_to_server",
        "done",
        100,
        "M1 — Device → Server",
        "DeviceID || SessionID",
        f"M1 received correctly from device {device_id}.",
        payload_preview=json_dumps({"device_id": device_id, "session_id": session_id}),
    )
    time.sleep(5)
    update_session(session_id, protocol_phase="m2_sent")
    insert_protocol_message(
        session_id,
        "M2",
        "server_to_device",
        "done",
        100,
        "M2 — Server → Device",
        "{C1, r1}",
        "Challenge generated and sent to device.",
        payload_preview=json_dumps({"C1": c1, "r1": b64e(r1)}),
    )
    insert_protocol_message(
        session_id,
        "M3",
        "device_to_server",
        "waiting",
        0,
        "M3 — Device → Server",
        "Enc(k1, r1 || t1 || {C2, r2})",
        "Waiting for encrypted payload from device.",
    )
    insert_protocol_message(
        session_id,
        "M4",
        "server_to_device",
        "waiting",
        0,
        "M4 — Server → Device",
        "Enc(k2 XOR t1, r2 || t2)",
        "Waiting for device verification.",
    )
    insert_protocol_message(
        session_id,
        "vault_update",
        "internal",
        "waiting",
        0,
        "Update Vault",
        "HMAC(current_vault, exchanged_data)",
        "The vault will be updated after mutual authentication.",
    )

    log_event("INFO", "M1 received, M2 generated and sent.", device_id=device_id, session_id=session_id)
    return jsonify({"ok": True, "message": "M2 generated", "C1": c1, "r1": b64e(r1)})

@app.route("/auth/respond", methods=["POST"])
def auth_respond() -> Any:
    """
    M3: Device responds to server's challenge.
    Server verifies M3, generates M4, updates vault, and establishes session key.
    This completes mutual authentication and enables secure data exchange.
    """
    rate_limit_response = check_rate_limit("auth_respond", RATE_LIMIT_AUTH_RESPOND_MAX)
    if rate_limit_response:
        return rate_limit_response
    cleanup_expired_sessions()
    body = request.get_json(force=True)
    device_id = body.get("device_id")
    session_id = body.get("session_id")
    ciphertext_b64 = body.get("ciphertext")

    if not device_id or not session_id or not ciphertext_b64:
        return jsonify({"ok": False, "error": "device_id, session_id and ciphertext are required"}), 400

    device = get_device(device_id)
    if not device:
        return jsonify({"ok": False, "error": f"Device {device_id} not registered"}), 404

    ctx = SESSION_CTX.get(session_id)
    if not ctx or ctx.get("device_id") != device_id:
        return jsonify({"ok": False, "error": "Session not valid or expired"}), 400

    key_size_bytes = int(device["key_size_bytes"])
    vault_blob = device["vault"]
    c1 = ctx["c1"]
    r1_expected = ctx["r1"]

    try:
        k1 = compute_k_from_indices(vault_blob, key_size_bytes, c1)
        ciphertext = b64d(ciphertext_b64)
        print("SERVER vault =", list(vault_blob))
        print("SERVER C1 =", c1)
        print("SERVER k1 =", list(k1))
        print("SERVER aes_key_M3 =", derive_aes_key(k1).hex())
        print("SERVER ciphertext_len =", len(ciphertext))
        plaintext = aes_decrypt(derive_aes_key(k1), ciphertext)
        payload = json.loads(plaintext.decode("utf-8"))
        r1_received = b64d(payload["r1"])
        t1 = b64d(payload["t1"])
        c2 = payload["C2"]
        r2 = b64d(payload["r2"])

        if r1_received != r1_expected:
            raise ValueError("Authentication failed")

        update_protocol_message(session_id, "M3", "done", 100, "M3 received and verified correctly.")
        update_session(
            session_id,
            protocol_phase="m3_sent",
            auth_device_status="success",
            r1=r1_received,
            t1=t1,
            r2=r2,
        )
        time.sleep(3)
        k2 = compute_k_from_indices(vault_blob, key_size_bytes, c2)
        t2 = os.urandom(16)
        expanded_k2 = k2 * 16
        response_material = xor_bytes(expanded_k2, t1)
        aes_key = derive_aes_key(response_material)
        m4_payload = json_dumps({"r2": b64e(r2), "t2": b64e(t2)}).encode("utf-8")
        m4_ciphertext = aes_encrypt(aes_key, m4_payload)
        session_key = xor_bytes(t1, t2)
        transcript = build_transcript(session_id, c1, r1_expected, t1, c2, r2, t2)
        new_vault = update_vault(vault_blob, transcript)

        conn = get_db()
        conn.execute(
            "UPDATE devices SET vault = ?, vault_version = vault_version + 1, updated_at = ? WHERE device_id = ?",
            (new_vault, utcnow_str(), device_id),
        )
        conn.commit()
        conn.close()

        SESSION_CTX[session_id].update(
            {
                "t1": t1,
                "t2": t2,
                "r2": r2,
                "c2": c2,
                "session_key": session_key,
                "authenticated": True,
                "auth_in_progress": False,
                "last_message_counter": -1,
            }
        )

        update_protocol_message(session_id, "M4", "done", 100, "M4 generated and sent correctly.")
        update_session(session_id, protocol_phase="m4_sent")
        time.sleep(5)
        update_protocol_message(session_id, "vault_update", "done", 100, "Vault updated on server.")
        update_session(session_id, protocol_phase="vault_updated")
        set_device_pending(session_id, False)
        update_session(
            session_id,
            protocol_phase="vault_updated",
            status="success",
            auth_server_status="success",
            session_key_generated=1,
            vault_status="updated",
            t2=t2,
            completed_at=utcnow_str(),
        )

        log_event("INFO", "M3 verified, M4 sent, mutual authentication successful.", device_id=device_id, session_id=session_id)
        log_event("INFO", f"Vault updated for {device_id}.", device_id=device_id, session_id=session_id)

        return jsonify(
            {
                "ok": True,
                "message": "M4 generated",
                "ciphertext": b64e(m4_ciphertext),
            }
        )

    except Exception as exc:
        if session_id in SESSION_CTX:
            SESSION_CTX[session_id]["auth_in_progress"] = False
        print("AUTH_RESPOND ERROR:", repr(exc))
        import traceback
        traceback.print_exc()
        update_protocol_message(session_id, "M3", "error", 100, "M3 verification failed.")
        update_session(
            session_id,
            protocol_phase="failed",
            status="failure",
            auth_device_status="failed",
            auth_server_status="failed",
            vault_status="error",
            completed_at=utcnow_str(),
        )
        log_event("ERROR", "Authentication failed.", device_id=device_id, session_id=session_id)
        return jsonify({"ok": False, "error": "Authentication failed"}), 400


@app.route("/session/data", methods=["POST"])
def session_data() -> Any:
    """
    Secure data exchange endpoint for authenticated devices.
    Receives encrypted sensor data, verifies HMAC, checks replay protection,
    and stores data. Only accessible after successful authentication.
    """
    body = request.get_json(force=True)
    device_id = body.get("device_id")
    session_id = body.get("session_id")
    ciphertext_b64 = body.get("ciphertext")

    if not device_id or not session_id or not ciphertext_b64:
        return jsonify({"ok": False, "error": "device_id, session_id and ciphertext are required"}), 400

    session = get_session_by_id(session_id)
    if not session:
        return jsonify({"ok": False, "error": "Session not found"}), 403

    if session["device_id"] != device_id:
        return jsonify({"ok": False, "error": "Session not associated with this device"}), 403

    if session["status"] != "success":
        return jsonify({"ok": False, "error": "Session not authenticated"}), 403

    completed_at = session["completed_at"]
    if completed_at:
        session_time = datetime.strptime(completed_at, "%Y-%m-%d %H:%M:%S")
        if datetime.now() - session_time > timedelta(seconds=60):
            return jsonify({"ok": False, "error": "Session expired"}), 403

    ctx = SESSION_CTX.get(session_id)
    if not ctx:
        return jsonify({"ok": False, "error": "Session context not available"}), 403

    t1 = ctx.get("t1")
    t2 = ctx.get("t2")

    if t1 is None or t2 is None:
        return jsonify({"ok": False, "error": "Session key not available"}), 403

    session_key = xor_bytes(t1, t2)

    try:
        ciphertext = b64d(ciphertext_b64)
        plaintext = aes_decrypt(session_key, ciphertext)
        payload = json.loads(plaintext.decode("utf-8"))
    except Exception:
        # FIX: Errore generico — nessun dettaglio sulla decifratura
        return jsonify({"ok": False, "error": "Payload not valid"}), 400
    
    received_hmac = payload.get("hmac")

    if not isinstance(received_hmac, str):
        return jsonify({"ok": False, "error": "HMAC not found or invalid"}), 400

    payload_for_mac = {
        "message_counter": payload.get("message_counter"),
        "temperature": payload.get("temperature"),
        "humidity": payload.get("humidity"),
        "battery": payload.get("battery"),
    }
    payload_for_mac_bytes = json_dumps(payload_for_mac).encode("utf-8")
    expected_hmac = compute_message_hmac(session_key, payload_for_mac_bytes)

    if not hmac.compare_digest(received_hmac, expected_hmac):
        return jsonify({"ok": False, "error": "HMAC not valid"}), 400

    message_counter = payload.get("message_counter")

    if not isinstance(message_counter, int):
        return jsonify({"ok": False, "error": "message_counter not found or invalid"}), 400

    last_counter = ctx.get("last_message_counter", -1)

    if message_counter <= last_counter:
        return jsonify({"ok": False, "error": "Replay detected or counter invalid"}), 409

    ctx["last_message_counter"] = message_counter

    temperature = payload.get("temperature")
    humidity = payload.get("humidity")
    battery = payload.get("battery")

    payload_json = json_dumps(
        {
            "temperature": temperature,
            "humidity": humidity,
            "battery": battery,
        }
    )

    conn = get_db()
    conn.execute(
        """
        INSERT INTO sensor_data(device_id, session_id, temperature, humidity, battery, payload_json, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (device_id, session_id, temperature, humidity, battery, payload_json, utcnow_str()),
    )
    conn.commit()
    conn.close()

    log_event(
        "INFO",
        f"Sensor's data received: temperature={temperature}, humidity={humidity}, battery={battery}",
        device_id=device_id,
        session_id=session_id,
    )

    return jsonify({"ok": True})


# ====
# Bootstrap
# ====

if __name__ == "__main__":
    """
    Application entry point.
    Starts Flask development server on all interfaces.
    In production, use a proper WSGI server.
    """
    app.run(host="0.0.0.0", port=5050, debug=False)
