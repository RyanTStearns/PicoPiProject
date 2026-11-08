"""
Pico Protocol Client -- Original Static Master-Key Scheme
--------------------------------------------------------------
Implements the device side of the handshake described in
gateway_protocol_v1.py. Edit DEVICE_ID per board before uploading.

Requires crypto_utils.py uploaded to the Pico alongside this file.
"""

import network
import socket
import time
import os
from crypto_utils import hmac_sha256

# ---------------------------------------------------------------------------
# Edit per device before uploading
# ---------------------------------------------------------------------------
DEVICE_ID = "Pico2W-1"  # change to "Pico2W-2" on the second board
MASTER_KEY = bytes.fromhex(
    "00112233445566778899aabbccddeeff00112233445566778899aabbccddee"
)  # must match the entry for this DEVICE_ID in gateway_protocol_v1.py

SSID = "StearnsGatewayAP"
PASSWORD = "E@tL0tsOfPi18!"
GATEWAY_IP = "192.168.4.1"
GATEWAY_PORT = 5000
NONCE_LEN = 16


def connect_wifi():
    wlan = network.WLAN(network.STA_IF)
    wlan.active(True)
    wlan.connect(SSID, PASSWORD)

    start = time.time()
    while wlan.status() == 1:
        if time.time() - start > 15:
            print("WiFi connect timed out.")
            return None
        time.sleep(0.5)

    if wlan.status() != 3:
        print("WiFi connect failed, status:", wlan.status())
        return None

    print("WiFi connected:", wlan.ifconfig())
    return wlan


def run_handshake():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5)
    s.connect((GATEWAY_IP, GATEWAY_PORT))

    # --- Step 1: send HELLO ---
    device_nonce = os.urandom(NONCE_LEN)
    hello_msg = b"HELLO|" + DEVICE_ID.encode() + b"|" + device_nonce
    s.send(hello_msg)
    print("Sent HELLO, nonce =", device_nonce.hex())

    # --- Step 2: receive CHALLENGE ---
    response = s.recv(256)
    parts = response.split(b"|")
    if len(parts) != 2 or parts[0] != b"CHALLENGE":
        print("Unexpected response:", response)
        s.close()
        return False

    gateway_nonce = parts[1]
    print("Received CHALLENGE, gateway_nonce =", gateway_nonce.hex())

    # --- Step 3: derive session key ---
    session_key = hmac_sha256(MASTER_KEY, device_nonce + gateway_nonce)
    print("Derived session key:", session_key.hex())

    # --- Step 4: send AUTH confirmation ---
    auth_tag = hmac_sha256(session_key, b"AUTH_CONFIRM")
    s.send(b"AUTH|" + auth_tag)

    # --- Step 5: read result ---
    result = s.recv(64)
    s.close()

    if result == b"AUTH_OK":
        print("Handshake SUCCESSFUL -- session key established.")
        return True
    else:
        print("Handshake FAILED:", result)
        return False


if __name__ == "__main__":
    wlan = connect_wifi()
    if wlan:
        run_handshake()
