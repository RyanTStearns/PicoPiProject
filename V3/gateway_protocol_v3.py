#!/usr/bin/env python3
"""
Gateway Protocol Server v3 -- Fixed Binary Framing
-------------------------------------------------------
Fixes two bugs present in v1/v2:
  1. Using "|" as a text delimiter on binary nonce data -- nonces are
     random bytes and can themselves contain the "|" byte (0x7c),
     corrupting message parsing roughly 1 in 16 handshakes.
  2. A single recv() call doesn't guarantee a complete message arrives
     in one read over a real network -- messages can arrive split
     across multiple TCP segments.

Wire format (all messages start with a 1-byte command code):
  HELLO     = 0x01 | 1-byte device_id length | device_id bytes | 16-byte nonce
  CHALLENGE = 0x02 | 16-byte nonce
  AUTH      = 0x03 | 32-byte HMAC tag
  AUTH_OK   = 0x04
  AUTH_FAIL = 0x05
  ERROR     = 0x06 | 1-byte error code

Requires crypto_utils.py in the same directory.

Run:
    python3 gateway_protocol_v3.py
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
TAG_LEN = 32

CMD_HELLO = 0x01
CMD_CHALLENGE = 0x02
CMD_AUTH = 0x03
CMD_AUTH_OK = 0x04
CMD_AUTH_FAIL = 0x05
CMD_ERROR = 0x06

ERR_BAD_HELLO = 0x01
ERR_UNKNOWN_DEVICE = 0x02
ERR_BAD_AUTH = 0x03


def recv_exact(sock, n):
    """Read exactly n bytes, looping as needed across multiple TCP reads."""
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Socket closed before expected data arrived")
        buf += chunk
    return buf


def init_log():
    file_exists = os.path.exists(LOG_FILE)
    f = open(LOG_FILE, "a", newline="")
    writer = csv.writer(f)
    if not file_exists:
        writer.writerow(["timestamp_iso", "device_id", "client_ip", "latency_ms", "outcome"])
    return f, writer


def handle_client(conn, addr, log_writer, log_file):
    start_time = time.monotonic()
    device_id = "unknown"
    outcome = "error"

    try:
        # --- Step 1: receive HELLO ---
        header = recv_exact(conn, 2)  # command byte + device_id length byte
        if header[0] != CMD_HELLO:
            conn.sendall(bytes([CMD_ERROR, ERR_BAD_HELLO]))
            outcome = "bad_hello"
            return

        id_len = header[1]
        device_id_bytes = recv_exact(conn, id_len)
        device_nonce = recv_exact(conn, NONCE_LEN)
        device_id = device_id_bytes.decode()

        if device_id not in MASTER_KEYS:
            conn.sendall(bytes([CMD_ERROR, ERR_UNKNOWN_DEVICE]))
            outcome = "unknown_device"
            return

        master_key = MASTER_KEYS[device_id]

        # --- Step 2: send CHALLENGE ---
        gateway_nonce = os.urandom(NONCE_LEN)
        conn.sendall(bytes([CMD_CHALLENGE]) + gateway_nonce)

        # --- Step 3: derive session key ---
        session_key = hmac_sha256(master_key, device_nonce + gateway_nonce)

        # --- Step 4: receive AUTH confirmation ---
        auth_header = recv_exact(conn, 1)
        if auth_header[0] != CMD_AUTH:
            conn.sendall(bytes([CMD_AUTH_FAIL]))
            outcome = "bad_auth_msg"
            return

        received_tag = recv_exact(conn, TAG_LEN)
        expected_tag = hmac_sha256(session_key, b"AUTH_CONFIRM")

        # --- Step 5: verify and respond ---
        if constant_time_compare(received_tag, expected_tag):
            conn.sendall(bytes([CMD_AUTH_OK]))
            outcome = "AUTH_OK"
        else:
            conn.sendall(bytes([CMD_AUTH_FAIL]))
            outcome = "AUTH_FAIL"

    except Exception as e:
        outcome = f"exception:{e}"

    finally:
        latency_ms = (time.monotonic() - start_time) * 1000
        timestamp_iso = datetime.now().isoformat()

        log_writer.writerow([timestamp_iso, device_id, addr[0], f"{latency_ms:.3f}", outcome])
        log_file.flush()

        print(f"[{timestamp_iso}] {device_id} ({addr[0]}) -> {outcome} in {latency_ms:.3f} ms")
        conn.close()


def main():
    log_file, log_writer = init_log()

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((HOST, PORT))
        server.listen(5)
        print(f"Protocol server (v3, fixed framing) listening on {HOST}:{PORT}\n")

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
