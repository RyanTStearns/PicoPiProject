"""
Pico Protocol Client v3 -- Fixed Binary Framing, Batch Runner
--------------------------------------------------------------
Matches gateway_protocol_v3.py's wire format. Fixes the delimiter
collision and partial-read bugs present in v1/v2.

Edit DEVICE_ID and MASTER_KEY per board before uploading.
Requires crypto_utils.py already on the Pico.
"""

import network
import socket
import time
import os
from crypto_utils import hmac_sha256

# ---------------------------------------------------------------------------
# Edit per device before uploading -- DOUBLE CHECK both lines match the
# same device! This mismatch caused the last round of failures.
# ---------------------------------------------------------------------------
DEVICE_ID = "Pico2W-1"
MASTER_KEY = bytes.fromhex(
    "00112233445566778899aabbccddeeff00112233445566778899aabbccddee"
)

SSID = "StearnsGatewayAP"
PASSWORD = "E@tL0tsOfPi18!"
GATEWAY_IP = "192.168.4.1"
GATEWAY_PORT = 5000
NONCE_LEN = 16
TAG_LEN = 32

CMD_HELLO = 0x01
CMD_CHALLENGE = 0x02
CMD_AUTH = 0x03
CMD_AUTH_OK = 0x04
CMD_AUTH_FAIL = 0x05
CMD_ERROR = 0x06

NUM_TRIALS = 30
DELAY_BETWEEN_SEC = 2


def recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Socket closed before expected data arrived")
        buf += chunk
    return buf


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

        # --- Step 1: send HELLO ---
        device_nonce = os.urandom(NONCE_LEN)
        device_id_bytes = DEVICE_ID.encode()
        msg = bytes([CMD_HELLO, len(device_id_bytes)]) + device_id_bytes + device_nonce
        s.send(msg)

        # --- Step 2: receive CHALLENGE ---
        header = recv_exact(s, 1)
        if header[0] != CMD_CHALLENGE:
            print(f"[{trial_num}/{NUM_TRIALS}] Unexpected command: {header[0]}")
            s.close()
            return False
        gateway_nonce = recv_exact(s, NONCE_LEN)

        # --- Step 3: derive session key ---
        session_key = hmac_sha256(MASTER_KEY, device_nonce + gateway_nonce)

        # --- Step 4: send AUTH confirmation ---
        auth_tag = hmac_sha256(session_key, b"AUTH_CONFIRM")
        s.send(bytes([CMD_AUTH]) + auth_tag)

        # --- Step 5: read result ---
        result = recv_exact(s, 1)
        s.close()

        success = (result[0] == CMD_AUTH_OK)
        print(f"[{trial_num}/{NUM_TRIALS}] {'OK' if success else 'FAILED'}")
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
