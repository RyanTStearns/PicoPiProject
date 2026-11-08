#!/usr/bin/env python3
"""
Precompute Marker Logger
---------------------------
Listens for short marker messages from a Pico marking the start and end
of its ephemeral-keypair precomputation window (done during idle time
between handshakes). Timestamps each marker on the GATEWAY's own clock
-- the same clock used everywhere else -- so these windows can be
correlated with power_log.csv exactly like handshake windows are.

Wire format (separate from the main protocol, its own port):
  MARKER = 1-byte type (0x10=START, 0x11=END) | 1-byte id_len | device_id bytes

Run:
    python3 precompute_marker_logger.py
"""

import socket
import os
import csv
import time
from datetime import datetime

HOST = "0.0.0.0"
PORT = 5002
LOG_FILE = "precompute_log.csv"

MARKER_START = 0x10
MARKER_END = 0x11


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
        writer.writerow(["timestamp_iso", "device_id", "marker_type"])
    return f, writer


def handle_client(conn, addr, log_writer, log_file):
    try:
        header = recv_exact(conn, 2)
        marker_type = header[0]
        id_len = header[1]
        device_id = recv_exact(conn, id_len).decode()

        timestamp_iso = datetime.now().isoformat()
        marker_name = "START" if marker_type == MARKER_START else "END"

        log_writer.writerow([timestamp_iso, device_id, marker_name])
        log_file.flush()

        print(f"[{timestamp_iso}] {device_id} precompute {marker_name}")

    except Exception as e:
        print(f"Marker error from {addr[0]}: {e}")
    finally:
        conn.close()


def main():
    log_file, log_writer = init_log()

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((HOST, PORT))
        server.listen(5)
        print(f"Precompute marker logger listening on {HOST}:{PORT}\n"
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
