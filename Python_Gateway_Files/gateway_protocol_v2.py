#!/usr/bin/env python3
"""
Gateway Protocol Server v2 -- Original Static Master-Key Scheme, with logging
-------------------------------------------------------------------------------
Same handshake as gateway_protocol_v1.py, but now records every handshake's
start time, end time, latency, device, and outcome to a CSV file --
this is your raw data source for the "original protocol" comparison arm.

Requires crypto_utils.py in the same directory.

Run:
    python3 gateway_protocol_v2.py
"""

import socket
import os
import csv
import time
from datetime import datetime
from crypto_utils import hmac_sha256, constant_time_compare

HOST = "0.0.0.0"
PORT = 5000
LOG_FILE = "handshake_log_original.csv"

MASTER_KEYS = {
    "Pico2W-1": bytes.fromhex("00112233445566778899aabbccddeeff00112233445566778899aabbccddee"),
    "Pico2W-2": bytes.fromhex("112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"),
}

NONCE_LEN = 16


def init_log():
    file_exists = os.path.exists(LOG_FILE)
    f = open(LOG_FILE, "a", newline="")
    writer = csv.writer(f)
    if not file_exists:
        writer.writerow([
            "timestamp_iso", "device_id", "client_ip",
            "latency_ms", "outcome"
        ])
    return f, writer


def handle_client(conn, addr, log_writer, log_file):
    start_time = time.monotonic()
    device_id = "unknown"
    outcome = "error"

    try:
        # --- Step 1: receive HELLO ---
        data = conn.recv(1024)
        parts = data.split(b"|")
        if len(parts) != 3 or parts[0] != b"HELLO":
            conn.sendall(b"ERROR|bad_hello")
            outcome = "bad_hello"
            return

        device_id = parts[1].decode()
        device_nonce = parts[2]

        if device_id not in MASTER_KEYS:
            conn.sendall(b"ERROR|unknown_device")
            outcome = "unknown_device"
            return

        master_key = MASTER_KEYS[device_id]

        # --- Step 2: send CHALLENGE ---
        gateway_nonce = os.urandom(NONCE_LEN)
        conn.sendall(b"CHALLENGE|" + gateway_nonce)

        # --- Step 3: derive session key ---
        session_key = hmac_sha256(master_key, device_nonce + gateway_nonce)

        # --- Step 4: receive AUTH confirmation ---
        data = conn.recv(1024)
        parts = data.split(b"|")
        if len(parts) != 2 or parts[0] != b"AUTH":
            conn.sendall(b"AUTH_FAIL")
            outcome = "bad_auth_msg"
            return

        received_tag = parts[1]
        expected_tag = hmac_sha256(session_key, b"AUTH_CONFIRM")

        # --- Step 5: verify and respond ---
        if constant_time_compare(received_tag, expected_tag):
            conn.sendall(b"AUTH_OK")
            outcome = "AUTH_OK"
        else:
            conn.sendall(b"AUTH_FAIL")
            outcome = "AUTH_FAIL"

    except Exception as e:
        outcome = f"exception:{e}"

    finally:
        latency_ms = (time.monotonic() - start_time) * 1000
        timestamp_iso = datetime.now().isoformat()

        log_writer.writerow([
            timestamp_iso, device_id, addr[0],
            f"{latency_ms:.3f}", outcome
        ])
        log_file.flush()

        print(f"[{timestamp_iso}] {device_id} ({addr[0]}) "
              f"-> {outcome} in {latency_ms:.3f} ms")

        conn.close()


def main():
    log_file, log_writer = init_log()

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((HOST, PORT))
        server.listen(5)
        print(f"Protocol server (v2, logging to {LOG_FILE}) listening on {HOST}:{PORT}\n")

        try:
            while True:
                conn, addr = server.accept()
                handle_client(conn, addr, log_writer, log_file)
        except KeyboardInterrupt:
            print("\nShutting down, closing log file.")
        finally:
            log_file.close()


if __name__ == "__main__":
    main()
