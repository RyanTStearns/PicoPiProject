#!/usr/bin/env python3
"""
Gateway Protocol Server -- Original Static Master-Key Scheme
---------------------------------------------------------------
Implements the gateway side of the Bin-Rabiah-style handshake:

    1. Device  -> Gateway : HELLO | device_id | device_nonce
    2. Gateway -> Device  : CHALLENGE | gateway_nonce
    3. Both derive: session_key = HMAC-SHA256(master_key, device_nonce || gateway_nonce)
    4. Device  -> Gateway : AUTH | HMAC(session_key, b"AUTH_CONFIRM")
    5. Gateway verifies and replies AUTH_OK or AUTH_FAIL

Requires crypto_utils.py in the same directory.

Run:
    python3 gateway_protocol_v1.py
"""

import socket
import os
from crypto_utils import hmac_sha256, constant_time_compare

HOST = "0.0.0.0"
PORT = 5000

# Pre-shared per-device master keys (hardcoded for this experiment --
# in a real deployment these would be provisioned securely per device)
MASTER_KEYS = {
    "Pico2W-1": bytes.fromhex("00112233445566778899aabbccddeeff00112233445566778899aabbccddee"),
    "Pico2W-2": bytes.fromhex("112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"),
}

NONCE_LEN = 16


def handle_client(conn, addr):
    try:
        # --- Step 1: receive HELLO ---
        data = conn.recv(1024)
        parts = data.split(b"|")
        if len(parts) != 3 or parts[0] != b"HELLO":
            print(f"[{addr[0]}] Malformed HELLO: {data}")
            conn.sendall(b"ERROR|bad_hello")
            return

        device_id = parts[1].decode()
        device_nonce = parts[2]

        if device_id not in MASTER_KEYS:
            print(f"[{addr[0]}] Unknown device_id: {device_id}")
            conn.sendall(b"ERROR|unknown_device")
            return

        master_key = MASTER_KEYS[device_id]
        print(f"[{addr[0]}] HELLO from {device_id}, nonce={device_nonce.hex()}")

        # --- Step 2: send CHALLENGE ---
        gateway_nonce = os.urandom(NONCE_LEN)
        conn.sendall(b"CHALLENGE|" + gateway_nonce)

        # --- Step 3: derive session key ---
        session_key = hmac_sha256(master_key, device_nonce + gateway_nonce)
        print(f"[{addr[0]}] Derived session key: {session_key.hex()}")

        # --- Step 4: receive AUTH confirmation ---
        data = conn.recv(1024)
        parts = data.split(b"|")
        if len(parts) != 2 or parts[0] != b"AUTH":
            print(f"[{addr[0]}] Malformed AUTH: {data}")
            conn.sendall(b"AUTH_FAIL")
            return

        received_tag = parts[1]
        expected_tag = hmac_sha256(session_key, b"AUTH_CONFIRM")

        # --- Step 5: verify and respond ---
        if constant_time_compare(received_tag, expected_tag):
            print(f"[{addr[0]}] {device_id} AUTH_OK -- handshake complete")
            conn.sendall(b"AUTH_OK")
        else:
            print(f"[{addr[0]}] {device_id} AUTH_FAIL -- tag mismatch")
            conn.sendall(b"AUTH_FAIL")

    except Exception as e:
        print(f"[{addr[0]}] Error: {e}")
    finally:
        conn.close()


def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((HOST, PORT))
        server.listen(5)
        print(f"Protocol server listening on {HOST}:{PORT}\n")

        while True:
            conn, addr = server.accept()
            handle_client(conn, addr)


if __name__ == "__main__":
    main()
