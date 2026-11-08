"""
Pico Protocol Client v2 -- Automated Batch Runner
-----------------------------------------------------
Same handshake as pico_protocol_v1.py, but runs it NUM_TRIALS times
automatically with a short delay between each, so you can collect a
real timing distribution rather than a single data point.

Edit DEVICE_ID and MASTER_KEY per board before uploading.
Requires crypto_utils.py already on the Pico.
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
)

SSID = "StearnsGatewayAP"
PASSWORD = "E@tL0tsOfPi18!"
GATEWAY_IP = "192.168.4.1"
GATEWAY_PORT = 5000
NONCE_LEN = 16

NUM_TRIALS = 30          # how many handshakes to run
DELAY_BETWEEN_SEC = 2    # pause between trials


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


def run_handshake(trial_num):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect((GATEWAY_IP, GATEWAY_PORT))

        device_nonce = os.urandom(NONCE_LEN)
        s.send(b"HELLO|" + DEVICE_ID.encode() + b"|" + device_nonce)

        response = s.recv(256)
        parts = response.split(b"|")
        if len(parts) != 2 or parts[0] != b"CHALLENGE":
            print(f"[{trial_num}] Unexpected response:", response)
            s.close()
            return False

        gateway_nonce = parts[1]
        session_key = hmac_sha256(MASTER_KEY, device_nonce + gateway_nonce)
        auth_tag = hmac_sha256(session_key, b"AUTH_CONFIRM")
        s.send(b"AUTH|" + auth_tag)

        result = s.recv(64)
        s.close()

        success = (result == b"AUTH_OK")
        print(f"[{trial_num}/{NUM_TRIALS}] {'OK' if success else 'FAILED'}: {result}")
        return success

    except Exception as e:
        print(f"[{trial_num}/{NUM_TRIALS}] Exception: {e}")
        return False


def main():
    wlan = connect_wifi()
    if not wlan:
        return

    successes = 0
    for i in range(1, NUM_TRIALS + 1):
        if run_handshake(i):
            successes += 1
        time.sleep(DELAY_BETWEEN_SEC)

    print(f"\nBatch complete: {successes}/{NUM_TRIALS} handshakes succeeded.")


if __name__ == "__main__":
    main()
