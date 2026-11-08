#!/usr/bin/env python3
"""
Gateway Protocol Server v4 -- Forward-Secret Extension
------------------------------------------------------------
Extends v3's handshake with an ephemeral X25519 Diffie-Hellman exchange.
The session key now depends on BOTH the static master key AND a fresh,
random elliptic-curve shared secret generated anew each handshake and
never transmitted or stored. Compromise of the master key alone is no
longer sufficient to recover past session keys -- this is the forward
secrecy property the original (v1-v3) protocol lacks.

Wire format (extends v3):
  HELLO     = 0x01 | 1-byte id_len | device_id | 16-byte nonce | 32-byte eph_pubkey
  CHALLENGE = 0x02 | 16-byte nonce | 32-byte eph_pubkey
  AUTH      = 0x03 | 32-byte HMAC tag
  AUTH_OK   = 0x04
  AUTH_FAIL = 0x05
  ERROR     = 0x06 | 1-byte error code

session_key = HMAC-SHA256(master_key, device_nonce || gateway_nonce || shared_secret)

Requires crypto_utils.py and x25519.py in the same directory.

Run:
    python3 gateway_protocol_v4_fs.py
"""

import socket
import os
import csv
import time
from datetime import datetime
from crypto_utils import hmac_sha256, constant_time_compare
import x25519

HOST = "0.0.0.0"
PORT = 5001  # different port from v3, so you can run both side by side
LOG_FILE = "handshake_log_forward_secret.csv"

MASTER_KEYS = {
    "Pico2W-1": bytes.fromhex("00112233445566778899aabbccddeeff00112233445566778899aabbccddee"),
    "Pico2W-2": bytes.fromhex("112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"),
}

NONCE_LEN = 16
TAG_LEN = 32
PUBKEY_LEN = 32

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
        writer.writerow([
            "timestamp_iso", "device_id", "client_ip",
            "total_latency_ms", "x25519_latency_ms", "outcome"
        ])
    return f, writer


def handle_client(conn, addr, log_writer, log_file):
    start_time = time.monotonic()
    device_id = "unknown"
    outcome = "error"
    x25519_ms = 0.0

    try:
        # --- Step 1: receive HELLO (now includes device's ephemeral pubkey) ---
        header = recv_exact(conn, 2)
        if header[0] != CMD_HELLO:
            conn.sendall(bytes([CMD_ERROR, ERR_BAD_HELLO]))
            outcome = "bad_hello"
            return

        id_len = header[1]
        device_id_bytes = recv_exact(conn, id_len)
        device_nonce = recv_exact(conn, NONCE_LEN)
        device_eph_pubkey = recv_exact(conn, PUBKEY_LEN)
        device_id = device_id_bytes.decode()

        if device_id not in MASTER_KEYS:
            conn.sendall(bytes([CMD_ERROR, ERR_UNKNOWN_DEVICE]))
            outcome = "unknown_device"
            return

        master_key = MASTER_KEYS[device_id]

        # --- Step 2: generate our own ephemeral keypair, send CHALLENGE ---
        x25519_start = time.monotonic()
        gateway_eph_priv = x25519.generate_private_key()
        gateway_eph_pub = x25519.generate_public_key(gateway_eph_priv)

        gateway_nonce = os.urandom(NONCE_LEN)
        conn.sendall(bytes([CMD_CHALLENGE]) + gateway_nonce + gateway_eph_pub)

        # --- Step 3: compute shared secret + derive session key ---
        shared_secret = x25519.compute_shared_secret(gateway_eph_priv, device_eph_pubkey)
        x25519_ms = (time.monotonic() - x25519_start) * 1000

        session_key = hmac_sha256(
            master_key, device_nonce + gateway_nonce + shared_secret
        )

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

        # Ephemeral keys and shared_secret go out of scope here and are
        # discarded -- they are never stored, logged, or reused.

    except Exception as e:
        outcome = f"exception:{e}"

    finally:
        total_ms = (time.monotonic() - start_time) * 1000
        timestamp_iso = datetime.now().isoformat()

        log_writer.writerow([
            timestamp_iso, device_id, addr[0],
            f"{total_ms:.3f}", f"{x25519_ms:.3f}", outcome
        ])
        log_file.flush()

        print(f"[{timestamp_iso}] {device_id} ({addr[0]}) -> {outcome} "
              f"total={total_ms:.3f}ms  x25519={x25519_ms:.3f}ms")

        conn.close()


def main():
    log_file, log_writer = init_log()

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((HOST, PORT))
        server.listen(5)
        print(f"Forward-secret protocol server listening on {HOST}:{PORT}\n"
              f"(logging to {LOG_FILE})\n")

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
