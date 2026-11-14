"""
Pico Protocol Client v6 -- Standalone, Self-Logging, Multi-Run
------------------------------------------------------------------
Same handshake, precompute and marker behaviour as v5 (precomp_marked),
changed only so the Pico can run with NO USB cable attached:

  * Save this file on the Pico as main.py so it starts on power-up.
  * Everything Thonny used to show is written to the Pico's own flash
    (pico_output_<id>.txt, plus per-trial rows in pico_trials_<id>.csv).
  * NUM_RUNS batches are run back to back, separated by a long idle gap
    (RUN_GAP_SEC) so each run is easy to pick out in the gateway's
    power_log / handshake_log / precompute_log.

Measurement hygiene:
  * Log lines are held in RAM during a run and written to flash only
    AFTER the run's last trial, inside the idle gap -- flash writes never
    land inside a handshake or precompute window.
  * If USB power is present at boot the batch is skipped, so plugging in
    to copy the logs off does not start a new run, and no measured run
    can happen with USB supplying part of the current.

Requires crypto_utils.py and x25519.py already on the Pico.
Requires gateway_protocol_v4_fs.py (port 5001) and
precompute_marker_logger.py (port 5002) running on the gateway.
"""

import network
import socket
import time
import os
import gc
from machine import Pin
from crypto_utils import hmac_sha256
import x25519

# ---------------------------------------------------------------------------
DEVICE_ID = "Pico2W-1"
MASTER_KEY = bytes.fromhex(
    "00112233445566778899aabbccddeeff00112233445566778899aabbccddee"
)

SSID = "StearnsGatewayAP"
PASSWORD = "E@tL0tsOfPi18!"
GATEWAY_IP = "192.168.4.1"
GATEWAY_PORT = 5001
MARKER_PORT = 5002
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

NUM_TRIALS = 30          # handshakes per run (same as v5)
DELAY_BETWEEN_SEC = 2    # idle between handshakes (same as v5)

NUM_RUNS = 5             # replaces the five manual tests a-e
START_DELAY_SEC = 30     # idle after power-up, before run 1 (baseline)
RUN_GAP_SEC = 60         # idle between runs -- the run separator in the logs

SKIP_IF_USB_POWERED = True

OUTPUT_FILE = "pico_output_" + DEVICE_ID + ".txt"
TRIALS_FILE = "pico_trials_" + DEVICE_ID + ".csv"
TRIALS_HEADER = "boot_id,run,trial,success,critical_path_ms,dh_ms,precompute_ms,ticks_ms"

# In-RAM buffers, flushed to flash only between runs.
_out_lines = []
_trial_rows = []


def log(msg=""):
    print(msg)
    _out_lines.append(msg)


def flush_logs():
    """Write buffered lines to flash. Call only while idle."""
    global _out_lines, _trial_rows
    try:
        if _out_lines:
            with open(OUTPUT_FILE, "a") as f:
                for line in _out_lines:
                    f.write(line + "\n")
        if _trial_rows:
            try:
                os.stat(TRIALS_FILE)
                need_header = False
            except OSError:
                need_header = True
            with open(TRIALS_FILE, "a") as f:
                if need_header:
                    f.write(TRIALS_HEADER + "\n")
                for row in _trial_rows:
                    f.write(",".join(str(v) for v in row) + "\n")
    except Exception as e:
        print("Log flush failed:", e)
    _out_lines = []
    _trial_rows = []
    gc.collect()


def usb_power_present():
    """True if 5V is present on the USB connector (VBUS sense, WL_GPIO2)."""
    try:
        return Pin("WL_GPIO2", Pin.IN).value() == 1
    except Exception as e:
        print("VBUS sense unavailable:", e)
        return False


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
        log(f"  (marker send failed: {e})")


def connect_wifi():
    wlan = network.WLAN(network.STA_IF)
    wlan.active(True)
    wlan.config(pm=0xa11140)
    if wlan.isconnected():
        return wlan
    wlan.connect(SSID, PASSWORD)

    start = time.time()
    while wlan.status() == 1:
        if time.time() - start > 15:
            log("WiFi connect timed out.")
            return None
        time.sleep(0.5)

    if wlan.status() != 3:
        log(f"WiFi connect failed, status: {wlan.status()}")
        return None

    log(f"WiFi connected: {wlan.ifconfig()}")
    return wlan


def connect_wifi_with_retry(attempts=5):
    for attempt in range(1, attempts + 1):
        wlan = connect_wifi()
        if wlan:
            return wlan
        log(f"WiFi attempt {attempt}/{attempts} failed, retrying in 5s")
        time.sleep(5)
    return None


def generate_keypair_timed():
    t0 = time.ticks_ms()
    priv = x25519.generate_private_key()
    pub = x25519.generate_public_key(priv)
    elapsed_ms = time.ticks_diff(time.ticks_ms(), t0)
    return priv, pub, elapsed_ms


def run_handshake(trial_num, device_eph_priv, device_eph_pub):
    s = None
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
            log(f"[{trial_num}/{NUM_TRIALS}] Unexpected command: {header[0]}")
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

        log(f"[{trial_num}/{NUM_TRIALS}] {'OK' if success else 'FAILED'}  "
            f"critical_path_total={total_ms}ms  dh={dh_ms}ms")

        return success, total_ms, dh_ms

    except Exception as e:
        log(f"[{trial_num}/{NUM_TRIALS}] Exception: {e}")
        try:
            if s:
                s.close()
        except Exception:
            pass
        return False, 0, 0


def run_batch(boot_id, run_num, next_priv, next_pub):
    """One run of NUM_TRIALS handshakes -- identical to a single v5 test."""
    log(f"===== RUN {run_num}/{NUM_RUNS} start (ticks_ms={time.ticks_ms()}) =====")

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

        _trial_rows.append((boot_id, run_num, i, 1 if success else 0,
                            total_ms, dh_ms, precompute_ms, time.ticks_ms()))

        remaining_delay = max(0, DELAY_BETWEEN_SEC - (precompute_ms / 1000))
        log(f"    (precomputed next keypair in {precompute_ms}ms, marked for "
            f"gateway, sleeping remaining {remaining_delay:.2f}s)")
        time.sleep(remaining_delay)

    log(f"\nRun {run_num} complete: {successes}/{NUM_TRIALS} handshakes succeeded.")
    if critical_path_times:
        avg_critical = sum(critical_path_times) / len(critical_path_times)
        avg_dh = sum(dh_times) / len(dh_times)
        log(f"Avg critical-path latency: {avg_critical:.1f} ms")
        log(f"Avg DH compute time:       {avg_dh:.1f} ms")
    log(f"===== RUN {run_num}/{NUM_RUNS} end (ticks_ms={time.ticks_ms()}) =====\n")

    return next_priv, next_pub


def main():
    if SKIP_IF_USB_POWERED and usb_power_present():
        print("USB power detected -- skipping the batch so no run is measured "
              "with USB attached. Logs on this Pico:", OUTPUT_FILE, TRIALS_FILE)
        return

    boot_id = "%08x" % int.from_bytes(os.urandom(4), "big")
    log(f"\n##### BOOT {boot_id}  device={DEVICE_ID}  runs={NUM_RUNS}  "
        f"trials={NUM_TRIALS}  run_gap={RUN_GAP_SEC}s #####")

    wlan = connect_wifi_with_retry()
    if not wlan:
        log("Giving up: no WiFi.")
        flush_logs()
        return

    log("\nGenerating initial ephemeral keypair (not counted in trial timing)...")
    next_priv, next_pub, keygen_ms = generate_keypair_timed()
    log(f"Initial keypair ready ({keygen_ms}ms, done before trials start)")
    log(f"Idling {START_DELAY_SEC}s before run 1 (baseline)\n")
    flush_logs()
    time.sleep(START_DELAY_SEC)

    for run_num in range(1, NUM_RUNS + 1):
        next_priv, next_pub = run_batch(boot_id, run_num, next_priv, next_pub)

        # Flash write happens here, at the start of the idle gap.
        flush_logs()
        if run_num < NUM_RUNS:
            time.sleep(RUN_GAP_SEC)

    log(f"All {NUM_RUNS} runs complete.")
    flush_logs()


if __name__ == "__main__":
    main()
