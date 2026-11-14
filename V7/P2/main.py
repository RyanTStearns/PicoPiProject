"""
Pico Protocol Client v7 -- Precomputed Keypair, Marked Precompute Window,
Gateway-Gated Session Start
------------------------------------------------------------------------------
Identical to v5b (pico_protocol_v5_precomp_marked_p1.py) EXCEPT for one
added step right after WiFi connects: this board now reports in to the
gateway's new session-gate server (port 5003) and BLOCKS there until the
gateway sends it an explicit "go" signal, instead of immediately starting
its 30-handshake batch.

This exists so the gateway's LCD dashboard (gateway_protocol_v7_lcd_dashboard.py)
can run the two boards SEQUENTIALLY (Testing session #1 = this board alone,
then Testing session #2 = Pico2W-2 alone) with both boards already powered
on, connected to WiFi, and idling -- matching the standalone methodology
validated in V6_Standalone, but now with synchronized on-screen status
instead of manually starting each board's script by hand.

Requires crypto_utils.py and x25519.py already on the Pico.
Requires gateway_protocol_v7_lcd_dashboard.py running on the gateway
(it replaces gateway_protocol_v4_fs.py + precompute_marker_logger.py --
it runs both of those plus the new gate server, all in one process).
"""

import network
import socket
import time
import os
from crypto_utils import hmac_sha256
import x25519

# ---------------------------------------------------------------------------
DEVICE_ID = "Pico2W-2"
MASTER_KEY = bytes.fromhex(
    "112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
)

SSID = "StearnsGatewayAP"
PASSWORD = "E@tL0tsOfPi18!"
GATEWAY_IP = "192.168.4.1"
GATEWAY_PORT = 5001
MARKER_PORT = 5002
GATE_PORT = 5003
NONCE_LEN = 16
TAG_LEN = 32
PUBKEY_LEN = 32

CMD_HELLO = 0x01
CMD_CHALLENGE = 0x02
CMD_AUTH = 0x03
CMD_AUTH_OK = 0x04
CMD_AUTH_FAIL = 0x05
CMD_ERROR = 0x06

MARKER_START = 0x10
MARKER_END = 0x11

GATE_HELLO = 0x20   # device_id follows, same length-prefixed format as markers
GATE_GO = 0x01       # the one byte the gateway sends back when it's this device's turn

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


def send_marker(marker_type):
    """Send a one-shot marker to the gateway's marker logger. Best-effort --
    a failure here shouldn't crash the batch run."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        s.connect((GATEWAY_IP, MARKER_PORT))
        device_id_bytes = DEVICE_ID.encode()
        s.send(bytes([marker_type, len(device_id_bytes)]) + device_id_bytes)
        s.close()
    except Exception as e:
        print(f"  (marker send failed: {e})")


def connect_wifi():
    wlan = network.WLAN(network.STA_IF)
    wlan.active(True)
    wlan.config(pm=0xa11140)
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


def wait_for_gateway_go():
    """Report in to the gateway's session-gate server and block until the
    gateway sends the one-byte GO signal for this device. Keeps retrying
    the connection every second in case the gateway dashboard script
    hasn't finished starting up yet."""
    device_id_bytes = DEVICE_ID.encode()
    print(f"\nConnected and idling -- waiting for the gateway to start "
          f"this board's testing session...")

    while True:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(None)  # block indefinitely once connected
            s.connect((GATEWAY_IP, GATE_PORT))
            s.send(bytes([GATE_HELLO, len(device_id_bytes)]) + device_id_bytes)
            signal = recv_exact(s, 1)
            s.close()
            if signal[0] == GATE_GO:
                print("Gateway signaled GO -- starting testing session now.\n")
                return
        except Exception as e:
            print(f"  (gate connection failed, retrying in 1s: {e})")
            time.sleep(1)


def generate_keypair_timed():
    t0 = time.ticks_ms()
    priv = x25519.generate_private_key()
    pub = x25519.generate_public_key(priv)
    elapsed_ms = time.ticks_diff(time.ticks_ms(), t0)
    return priv, pub, elapsed_ms


def run_handshake(trial_num, device_eph_priv, device_eph_pub):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(10)
        s.connect((GATEWAY_IP, GATEWAY_PORT))

        trial_start = time.ticks_ms()

        device_nonce = os.urandom(NONCE_LEN)
        device_id_bytes = DEVICE_ID.encode()
        msg = (
            bytes([CMD_HELLO, len(device_id_bytes)])
            + device_id_bytes
            + device_nonce
            + device_eph_pub
        )
        s.send(msg)

        header = recv_exact(s, 1)
        if header[0] != CMD_CHALLENGE:
            print(f"[{trial_num}/{NUM_TRIALS}] Unexpected command: {header[0]}")
            s.close()
            return False, 0, 0

        gateway_nonce = recv_exact(s, NONCE_LEN)
        gateway_eph_pub = recv_exact(s, PUBKEY_LEN)

        t1 = time.ticks_ms()
        shared_secret = x25519.compute_shared_secret(device_eph_priv, gateway_eph_pub)
        dh_ms = time.ticks_diff(time.ticks_ms(), t1)

        session_key = hmac_sha256(MASTER_KEY, device_nonce + gateway_nonce + shared_secret)

        auth_tag = hmac_sha256(session_key, b"AUTH_CONFIRM")
        s.send(bytes([CMD_AUTH]) + auth_tag)

        result = recv_exact(s, 1)
        s.close()

        total_ms = time.ticks_diff(time.ticks_ms(), trial_start)
        success = (result[0] == CMD_AUTH_OK)

        print(f"[{trial_num}/{NUM_TRIALS}] {'OK' if success else 'FAILED'}  "
              f"critical_path_total={total_ms}ms  dh={dh_ms}ms")

        return success, total_ms, dh_ms

    except Exception as e:
        print(f"[{trial_num}/{NUM_TRIALS}] Exception: {e}")
        return False, 0, 0


def main():
    wlan = connect_wifi()
    if not wlan:
        return

    # NEW in v7: idle here (gateway is reading our current draw as "idle
    # power" and showing it on our LCD) until the gateway's dashboard
    # script says it's our turn.
    wait_for_gateway_go()

    print("Generating initial ephemeral keypair (not counted in trial timing)...")
    next_priv, next_pub, keygen_ms = generate_keypair_timed()
    print(f"Initial keypair ready ({keygen_ms}ms, done before trials start)\n")

    successes = 0
    critical_path_times = []
    dh_times = []

    for i in range(1, NUM_TRIALS + 1):
        current_priv, current_pub = next_priv, next_pub

        success, total_ms, dh_ms = run_handshake(i, current_priv, current_pub)
        if success:
            successes += 1
            critical_path_times.append(total_ms)
            dh_times.append(dh_ms)

        # --- Mark, precompute, mark ---
        send_marker(MARKER_START)
        next_priv, next_pub, precompute_ms = generate_keypair_timed()
        send_marker(MARKER_END)

        remaining_delay = max(0, DELAY_BETWEEN_SEC - (precompute_ms / 1000))
        print(f"    (precomputed next keypair in {precompute_ms}ms, marked for "
              f"gateway, sleeping remaining {remaining_delay:.2f}s)")
        time.sleep(remaining_delay)

    print(f"\nBatch complete: {successes}/{NUM_TRIALS} handshakes succeeded.")
    if critical_path_times:
        avg_critical = sum(critical_path_times) / len(critical_path_times)
        avg_dh = sum(dh_times) / len(dh_times)
        print(f"Avg critical-path latency: {avg_critical:.1f} ms")
        print(f"Avg DH compute time:       {avg_dh:.1f} ms")


if __name__ == "__main__":
    main()
