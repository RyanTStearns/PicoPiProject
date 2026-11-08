#!/usr/bin/env python3
"""
Gateway Connection Listener
----------------------------
Minimal TCP server to confirm each Pico 2 W can reach the gateway
over the isolated access point network. Not the real protocol server --
just a connectivity smoke test.

Run on the gateway:
    python3 gateway_listener.py
"""

import socket

HOST = "0.0.0.0"   # listen on all interfaces, including the AP's 192.168.4.1
PORT = 5000

def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((HOST, PORT))
        server.listen(5)
        print(f"Listening on {HOST}:{PORT} -- waiting for Pico connections...\n")

        while True:
            conn, addr = server.accept()
            with conn:
                data = conn.recv(1024)
                message = data.decode("utf-8", errors="replace").strip()
                print(f"Received from {addr[0]}: {message}")
                conn.sendall(b"ACK from gateway\n")

if __name__ == "__main__":
    main()
