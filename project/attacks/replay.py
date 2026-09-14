"""
Replay Attack Validation Demonstration

This script demonstrates replay attack protection in the IoT authentication system.
It first completes a legitimate authentication flow with the target device, derives the
session key, sends one authenticated /session/data payload, and then resends the exact
same ciphertext to verify that the server detects and rejects replayed messages.

The test demonstrates that the protocol relies on message counters and HMAC validation
to prevent attackers from reusing previously captured encrypted sensor packets. A
vulnerable system would accept the duplicated ciphertext as fresh telemetry, while the
expected secure behavior is to reject the second request as a replay or invalid counter.

This demonstration highlights the importance of anti-replay controls in IoT systems,
where captured network messages could otherwise be resent to forge stale sensor readings
or trigger unauthorized state changes.

Output:

============================================================
REPLAY VALIDATION TEST
============================================================

[1] /auth/start
STATUS: 200
BODY: {"C1":[1,3,10],"message":"M2 generated","ok":true,"r1":"rw=="}


[2] /auth/respond
STATUS: 200
BODY: {"ciphertext":"LQHcQhXp5rqXqNQB2G3yQDZpeQa2he6guB85G1yz58gHpMSo7Jfv781r5Vkyi7pcePHFwLKg1kCWukwQLg6iL8ws3/O5wEsf9+fyOwwMBs47TLkWFisITl8adkDxzZRg","message":"M4 generated","ok":true}


[3] Authentication completed
session_key = 074987e56f5e581fbae1217388aa3da5

[4] /session/data first send
STATUS: 200
BODY: {"ok":true}


[5] /session/data replay same ciphertext
STATUS: 409
BODY: {"error":"Replay detected or counter invalid","ok":false}


Expected behavior:
•⁠  first send accepted
•⁠  second identical send rejected as replay / invalid counter
============================================================
"""

#!/usr/bin/env python3
import base64
import json
import os
import hashlib
import hmac
import requests

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

TARGET = "http://188.218.211.175:5050"
DEVICE_ID = "ESP8266-01"

# Initial vault used by your project
VAULT = bytes([214, 249, 165, 110, 34, 247, 200, 70, 19, 83, 53, 38])


def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode()


def b64d(data: str) -> bytes:
    return base64.b64decode(data.encode())


def derive_aes_key(material: bytes) -> bytes:
    return hashlib.sha256(material).digest()[:16]


def compute_k(vault: bytes, indices) -> bytes:
    k = 0
    for i in indices:
        k ^= vault[i]
    return bytes([k])


def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def aes_cbc_encrypt_to_base64(key: bytes, plaintext: bytes) -> str:
    iv = os.urandom(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ct = cipher.encrypt(pad(plaintext, 16))
    return b64e(iv + ct)


def aes_cbc_decrypt_from_base64(key: bytes, ciphertext_b64: str) -> bytes:
    raw = b64d(ciphertext_b64)
    iv, ct = raw[:16], raw[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ct), 16)


def choose_distinct_c2(c1):
    out = []
    for i in range(len(VAULT)):
        if i not in c1:
            out.append(i)
        if len(out) == 3:
            break
    return out


def post_json(path: str, body: dict):
    return requests.post(f"{TARGET}{path}", json=body, timeout=10)


def main():
    print("=" * 60)
    print("REPLAY VALIDATION TEST")
    print("=" * 60)

    session_id = "local-replay-test-001"

    # Step 1: /auth/start
    print("\n[1] /auth/start")
    r = post_json("/auth/start", {
        "device_id": DEVICE_ID,
        "session_id": session_id
    })
    print("STATUS:", r.status_code)
    print("BODY:", r.text)
    r.raise_for_status()

    m2 = r.json()
    c1 = m2["C1"]
    r1 = b64d(m2["r1"])

    # Step 2: derive key for M3
    k1 = compute_k(VAULT, c1)
    aes_key_m3 = derive_aes_key(k1)

    # Step 3: build M3
    c2 = choose_distinct_c2(c1)
    r2 = os.urandom(16)
    t1 = os.urandom(16)

    m3_plain = {
        "r1": b64e(r1),
        "t1": b64e(t1),
        "C2": c2,
        "r2": b64e(r2),
    }
    m3_plain_bytes = json.dumps(m3_plain, separators=(",", ":")).encode()
    m3_cipher = aes_cbc_encrypt_to_base64(aes_key_m3, m3_plain_bytes)

    print("\n[2] /auth/respond")
    r = post_json("/auth/respond", {
        "device_id": DEVICE_ID,
        "session_id": session_id,
        "ciphertext": m3_cipher
    })
    print("STATUS:", r.status_code)
    print("BODY:", r.text)
    r.raise_for_status()

    m4 = r.json()
    m4_cipher = m4["ciphertext"]

    # Step 4: derive key for M4 and decrypt it
    k2 = compute_k(VAULT, c2)
    response_material = xor_bytes(bytes([k2[0]]) * 16, t1)
    aes_key_m4 = derive_aes_key(response_material)

    m4_plain = json.loads(aes_cbc_decrypt_from_base64(aes_key_m4, m4_cipher).decode())
    r2_check = b64d(m4_plain["r2"])
    t2 = b64d(m4_plain["t2"])

    if r2_check != r2:
        raise RuntimeError("Server authentication failed: r2 mismatch")

    session_key = xor_bytes(t1, t2)
    print("\n[3] Authentication completed")
    print("session_key =", session_key.hex())

    # Step 5: build one valid /session/data ciphertext
    message_counter = 0
    mac_payload = {
        "message_counter": message_counter,
        "temperature": 22.5,
        "humidity": 45.0,
        "battery": 95
    }
    mac_payload_bytes = json.dumps(mac_payload, separators=(",", ":")).encode()
    mac_hex = hmac.new(session_key, mac_payload_bytes, hashlib.sha256).hexdigest()

    full_payload = {
        "message_counter": message_counter,
        "temperature": 22.5,
        "humidity": 45.0,
        "battery": 95,
        "hmac": mac_hex
    }
    full_payload_bytes = json.dumps(full_payload, separators=(",", ":")).encode()
    valid_ciphertext = aes_cbc_encrypt_to_base64(session_key, full_payload_bytes)

    body = {
        "device_id": DEVICE_ID,
        "session_id": session_id,
        "ciphertext": valid_ciphertext
    }

    # Step 6: first valid send
    print("\n[4] /session/data first send")
    r = post_json("/session/data", body)
    print("STATUS:", r.status_code)
    print("BODY:", r.text)

    # Step 7: replay same ciphertext
    print("\n[5] /session/data replay same ciphertext")
    r = post_json("/session/data", body)
    print("STATUS:", r.status_code)
    print("BODY:", r.text)

    print("\nExpected behavior:")
    print("- first send accepted")
    print("- second identical send rejected as replay / invalid counter")
    print("=" * 60)


if __name__ == "__main__":
    main()