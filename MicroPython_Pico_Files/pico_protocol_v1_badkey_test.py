"""
Pico Protocol Client -- DELIBERATE BAD KEY TEST
-------------------------------------------------
Identical to pico_protocol_v1.py EXCEPT the master key has a single
byte deliberately changed (first byte: 0x00 -> 0x01). Use this to
confirm the gateway correctly returns AUTH_FAIL when the derived
session key doesn't match -- i.e. that your authentication check is
actually doing something, not silently always passing.

Run this once, confirm you see "Handshake FAILED: b'AUTH_FAIL'",
then go back to the correct pico_protocol_v1.py for normal use.
"""

import network
import socket
import time
import os
from crypto_utils import hmac_sha256

# ---------------------------------------------------------------------------
DEVICE_ID = "Pico2W-1"   # match whichever device you're testing with

# Correct key for Pico2W-1 is:
#   00112233445566778899aabbccddeeff00112233445566778899aabbccddee
# Below: first byte changed 00 -> 01, everything else identical.
MASTER_KEY = bytes.fromhex(
    "01112233445566778899aabbccddeeff00112233445566778899aabbccddee"
)

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

    device_nonce = os.urandom(NONCE_LEN)
    s.send(b"HELLO|" + DEVICE_ID.encode() + b"|" + device_nonce)
    print("Sent HELLO, nonce =", device_nonce.hex())

    response = s.recv(256)
    parts = response.split(b"|")
    if len(parts) != 2 or parts[0] != b"CHALLENGE":
        print("Unexpected response:", response)
        s.close()
        return False

    gateway_nonce = parts[1]
    print("Received CHALLENGE, gateway_nonce =", gateway_nonce.hex())

    # This will produce a DIFFERENT session key than the gateway computes,
    # since MASTER_KEY here doesn't match what's in MASTER_KEYS on the gateway.
    session_key = hmac_sha256(MASTER_KEY, device_nonce + gateway_nonce)
    print("Derived (incorrect) session key:", session_key.hex())

    auth_tag = hmac_sha256(session_key, b"AUTH_CONFIRM")
    s.send(b"AUTH|" + auth_tag)

    result = s.recv(64)
    s.close()

    if result == b"AUTH_OK":
        print("UNEXPECTED: Handshake succeeded with a bad key! "
              "Something is wrong with the gateway's verification logic.")
        return True
    else:
        print("Handshake FAILED as expected:", result)
        print("This confirms the gateway correctly rejects a mismatched key.")
        return False


if __name__ == "__main__":
    wlan = connect_wifi()
    if wlan:
        run_handshake()
