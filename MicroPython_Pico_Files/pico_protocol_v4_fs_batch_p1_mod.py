"""
Pico Protocol Client v4 -- Forward-Secret Extension, Batch Runner
------------------------------------------------------------------------
Runs the X25519 forward-secret handshake NUM_TRIALS times automatically,
mirroring pico_protocol_v3_batch.py so the two datasets are directly
comparable (same trial count, same device, same gateway).

Edit DEVICE_ID and MASTER_KEY per board before uploading.
Requires crypto_utils.py and x25519.py already on the Pico.
"""

import network
import socket
import time
import os
from crypto_utils import hmac_sha256
import x25519

# ---------------------------------------------------------------------------
# Edit per device before uploading -- double check these match each other!
# ---------------------------------------------------------------------------
DEVICE_ID = "Pico2W-1"
MASTER_KEY = bytes.fromhex(
    "00112233445566778899aabbccddeeff00112233445566778899aabbccddee"
)

SSID = "StearnsGatewayAP"
PASSWORD = "E@tL0tsOfPi18!"
GATEWAY_IP = "192.168.4.1"
GATEWAY_PORT = 5001
NONCE_LEN = 16
TAG_LEN = 32
PUBKEY_LEN = 32

CMD_HELLO = 0x01
CMD_CHALLENGE = 0x02
CMD_AUTH = 0x03
CMD_AUTH_OK = 0x04
CMD_AUTH_FAIL = 0x05
CMD_ERROR = 0x06

NUM_TRIALS = 30
DELAY_BETWEEN_SEC = 2  # pause between trials, on top of handshake time itself


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
    wlan.config(pm=0xa11140)  # disable WiFi power-save mode
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
        s.settimeout(10)
        s.connect((GATEWAY_IP, GATEWAY_PORT))

        trial_start = time.ticks_ms()

        # --- Generate ephemeral keypair ---
        t0 = time.ticks_ms()
        device_eph_priv = x25519.generate_private_key()
        device_eph_pub = x25519.generate_public_key(device_eph_priv)
        keygen_ms = time.ticks_diff(time.ticks_ms(), t0)

        # --- Step 1: send HELLO ---
        device_nonce = os.urandom(NONCE_LEN)
        device_id_bytes = DEVICE_ID.encode()
        msg = (
            bytes([CMD_HELLO, len(device_id_bytes)])
            + device_id_bytes
            + device_nonce
            + device_eph_pub
        )
        s.send(msg)

        # --- Step 2: receive CHALLENGE ---
        header = recv_exact(s, 1)
        if header[0] != CMD_CHALLENGE:
            print(f"[{trial_num}/{NUM_TRIALS}] Unexpected command: {header[0]}")
            s.close()
            return False, 0, 0
        gateway_nonce = recv_exact(s, NONCE_LEN)
        gateway_eph_pub = recv_exact(s, PUBKEY_LEN)

        # --- Step 3: compute shared secret + derive session key ---
        t1 = time.ticks_ms()
        shared_secret = x25519.compute_shared_secret(device_eph_priv, gateway_eph_pub)
        dh_ms = time.ticks_diff(time.ticks_ms(), t1)

        session_key = hmac_sha256(MASTER_KEY, device_nonce + gateway_nonce + shared_secret)

        # --- Step 4: send AUTH confirmation ---
        auth_tag = hmac_sha256(session_key, b"AUTH_CONFIRM")
        s.send(bytes([CMD_AUTH]) + auth_tag)

        # --- Step 5: read result ---
        result = recv_exact(s, 1)
        s.close()

        total_ms = time.ticks_diff(time.ticks_ms(), trial_start)
        success = (result[0] == CMD_AUTH_OK)

        print(f"[{trial_num}/{NUM_TRIALS}] {'OK' if success else 'FAILED'}  "
              f"total={total_ms}ms  keygen={keygen_ms}ms  dh={dh_ms}ms")

        return success, keygen_ms, dh_ms

    except Exception as e:
        print(f"[{trial_num}/{NUM_TRIALS}] Exception: {e}")
        return False, 0, 0


def main():
    wlan = connect_wifi()
    if not wlan:
        return

    successes = 0
    keygen_times = []
    dh_times = []

    for i in range(1, NUM_TRIALS + 1):
        success, keygen_ms, dh_ms = run_handshake(i)
        if success:
            successes += 1
            keygen_times.append(keygen_ms)
            dh_times.append(dh_ms)
        time.sleep(DELAY_BETWEEN_SEC)

    print(f"\nBatch complete: {successes}/{NUM_TRIALS} handshakes succeeded.")
    if keygen_times:
        print(f"Avg keygen time: {sum(keygen_times)/len(keygen_times):.1f} ms")
        print(f"Avg DH compute time: {sum(dh_times)/len(dh_times):.1f} ms")


if __name__ == "__main__":
    main()
