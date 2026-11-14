#!/usr/bin/env python3
"""
Gateway Protocol Server v7 -- LCD Status Dashboard + Sequential Session Gate
------------------------------------------------------------------------------
Combines everything that used to be three separate processes --
gateway_protocol_v4_fs.py (handshake protocol, port 5001),
precompute_marker_logger.py (port 5002), and an un-checked-in INA219
power-polling loop -- into ONE process, adds a new session-gate server
(port 5003) that holds each Pico idle after it connects to WiFi until
this script tells it to start, and drives two 16x2 I2C LCDs through the
exact status sequence below.

Protocol wire format and crypto are UNCHANGED from v4_fs/v5b -- this is
a display/orchestration layer on top of the same forward-secret,
precomputed-keypair protocol already validated in V5_PreComp_Marked and
V6_Standalone. It requires the new pico_protocol_v7_fs_precomp_gated_p1.py
/ _p2.py firmware (adds the "wait for gateway GO" step after WiFi
connects; otherwise identical to the v5b firmware).

Status sequence (exactly as specified):
  1. Both boards connect to WiFi and idle. Each board's LCD shows:
       "Pico 2W-x is connected."
       "Current power draw: <live, updating>"
     (long lines scroll in place on the 16-char display)
  2. Once BOTH boards are confirmed connected, wait 15s, then send GO to
     Pico2W-1 and show on its LCD:
       "Testing #1 session about to begin."
       "Pico 2W-1 is active......"
  3. 15s after that (independent of real handshake progress -- this is a
     fixed on-screen countdown), switch Pico2W-1's LCD to:
       "Analyzing handshakes on Pico2W-1"
       "Real-time power draw: <live, updating>"
     and leave it there, updating live, until Pico2W-1's 30-handshake
     batch completes.
  4. On completion, show for 10s:
       "Testing #1 session is complete."
       "Preparing for Testing session #2"
  5. Send GO to Pico2W-2 and show on ITS LCD for 15s:
       "Testing #2 session about to begin."
       "Pico 2W-2 is active......"
  6. 15s after that, switch to:
       "Analyzing handshakes on Pico2W-2"
       "Real-time power draw: <live, updating>"
     until Pico2W-2's batch completes.
  7. On completion, show on BOTH LCDs for 10s (then hold):
       "Testing session completed"

Design notes / things to verify on your hardware before running:
  - LCD1_ADDR / LCD2_ADDR below are guesses (0x27, 0x3F -- the common
    factory defaults for two PCF8574 backpacks). Run `i2cdetect -y 1`
    and fix these constants if your addresses differ. The INA219
    sensors are already confirmed at 0x40 (Pico2W-1) / 0x41 (Pico2W-2)
    from the existing wiring (Section 3.8) -- your two LCDs must be at
    two OTHER addresses.
  - "Connected" is inferred from INA219 current crossing
    CONNECTED_CURRENT_THRESHOLD_MA, since the gateway has no other way
    to know a board is powered/associated before it reaches the gate
    server. Idle current has historically been ~50-70 mA on this rig
    (Section 4.5/4.9), so the default 15 mA threshold has comfortable
    margin against a powered-off board (~0 mA) -- adjust if your boards
    idle lower than that.
  - Target handshake count per session is 30 (matches NUM_TRIALS in the
    Pico firmware everywhere else in this project). A session is also
    declared complete if no handshake activity arrives for
    SESSION_QUIET_TIMEOUT_SEC after having seen at least one, as a
    safety net against hanging forever on a dropped final handshake.
  - While device A is "active" (sessions 2-3 or 5-6 above), the OTHER
    device's LCD is left showing its own live idle-power display from
    step 1 -- the spec doesn't say otherwise, and it's the most useful
    default (it's still real, live sensor data). Change
    `_idle_message_for` if you'd rather it show something else (e.g. a
    "waiting its turn" message).

Requires: pip install adafruit-circuitpython-ina219 adafruit-blinka smbus2
Requires crypto_utils.py and x25519.py in the same directory.
Requires lcd1602_i2c.py (shipped alongside this file) in the same directory.

Run:
    python3 gateway_protocol_v7_lcd_dashboard.py
"""

import os
import csv
import socket
import threading
import time
from datetime import datetime

import board
import busio
from adafruit_ina219 import INA219

from crypto_utils import hmac_sha256, constant_time_compare
import x25519
from lcd1602_i2c import open_lcd, LCDStatusDisplay

# ---------------------------------------------------------------------------
# Hardware addresses -- CONFIRM with `i2cdetect -y 1` before running.
INA_ADDR = {"Pico2W-1": 0x40, "Pico2W-2": 0x41}
LCD1_ADDR = 0x27   # paired with Pico2W-1
LCD2_ADDR = 0x3F   # paired with Pico2W-2
I2C_BUS_NUM = 1    # Raspberry Pi default I2C bus for smbus2

# ---------------------------------------------------------------------------
HOST = "0.0.0.0"
HANDSHAKE_PORT = 5001
MARKER_PORT = 5002
GATE_PORT = 5003

HANDSHAKE_LOG_FILE = "handshake_log_forward_secret.csv"
PRECOMPUTE_LOG_FILE = "precompute_log.csv"
POWER_LOG_FILE = "power_log.csv"

MASTER_KEYS = {
    "Pico2W-1": bytes.fromhex("00112233445566778899aabbccddeeff00112233445566778899aabbccddee"),
    "Pico2W-2": bytes.fromhex("112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"),
}
DEVICE_ORDER = ["Pico2W-1", "Pico2W-2"]  # session #1 = first, session #2 = second

NONCE_LEN = 16
TAG_LEN = 32
PUBKEY_LEN = 32

CMD_HELLO, CMD_CHALLENGE, CMD_AUTH = 0x01, 0x02, 0x03
CMD_AUTH_OK, CMD_AUTH_FAIL, CMD_ERROR = 0x04, 0x05, 0x06
ERR_BAD_HELLO, ERR_UNKNOWN_DEVICE, ERR_BAD_AUTH = 0x01, 0x02, 0x03

MARKER_START, MARKER_END = 0x10, 0x11
GATE_HELLO = 0x20
GATE_GO = 0x01

CONNECTED_CURRENT_THRESHOLD_MA = 15.0
TARGET_HANDSHAKES = 30
SESSION_QUIET_TIMEOUT_SEC = 8.0

POWER_POLL_INTERVAL_SEC = 0.05     # how often INA219 is sampled/logged
LCD_REFRESH_INTERVAL_SEC = 0.4     # how often the LCDs are updated/scrolled
CONNECT_HOLD_SEC = 15
ANNOUNCE_SEC = 15
COMPLETE_HOLD_SEC = 10


# ---------------------------------------------------------------------------
# Shared state, protected by one lock (contention here is negligible --
# updates are small dict writes, not held across I/O).
class SharedState:
    def __init__(self):
        self.lock = threading.Lock()
        self.latest_power = {d: {"current_ma": 0.0, "power_w": 0.0, "voltage_v": 0.0} for d in DEVICE_ORDER}
        self.handshake_counts = {d: 0 for d in DEVICE_ORDER}
        self.last_handshake_ts = {d: None for d in DEVICE_ORDER}
        self.gate_sockets = {}  # device_id -> connected socket, waiting for GO

    def update_power(self, device, current_ma, power_w, voltage_v):
        with self.lock:
            self.latest_power[device] = {
                "current_ma": current_ma, "power_w": power_w, "voltage_v": voltage_v
            }

    def get_power(self, device):
        with self.lock:
            return dict(self.latest_power[device])

    def record_handshake(self, device):
        with self.lock:
            self.handshake_counts[device] += 1
            self.last_handshake_ts[device] = time.monotonic()
            return self.handshake_counts[device]

    def get_handshake_count(self, device):
        with self.lock:
            return self.handshake_counts[device]

    def get_last_handshake_ts(self, device):
        with self.lock:
            return self.last_handshake_ts[device]

    def register_gate_socket(self, device, sock):
        with self.lock:
            self.gate_sockets[device] = sock

    def send_go(self, device):
        with self.lock:
            sock = self.gate_sockets.pop(device, None)
        if sock is None:
            print(f"  WARNING: no gate connection registered yet for {device}; "
                  f"it will get GO as soon as it reports in.")
            return False
        try:
            sock.sendall(bytes([GATE_GO]))
            sock.close()
            return True
        except Exception as e:
            print(f"  WARNING: failed to send GO to {device}: {e}")
            return False


STATE = SharedState()


def recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Socket closed before expected data arrived")
        buf += chunk
    return buf


def init_csv_log(path, header):
    file_exists = os.path.exists(path)
    f = open(path, "a", newline="")
    writer = csv.writer(f)
    if not file_exists:
        writer.writerow(header)
    return f, writer


# ---------------------------------------------------------------------------
# 1) Handshake protocol server (port 5001) -- unchanged wire format from v4_fs
def handle_handshake_client(conn, addr, log_writer, log_file):
    start_time = time.monotonic()
    device_id = "unknown"
    outcome = "error"
    x25519_ms = 0.0

    try:
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

        x25519_start = time.monotonic()
        gateway_eph_priv = x25519.generate_private_key()
        gateway_eph_pub = x25519.generate_public_key(gateway_eph_priv)

        gateway_nonce = os.urandom(NONCE_LEN)
        conn.sendall(bytes([CMD_CHALLENGE]) + gateway_nonce + gateway_eph_pub)

        shared_secret = x25519.compute_shared_secret(gateway_eph_priv, device_eph_pubkey)
        x25519_ms = (time.monotonic() - x25519_start) * 1000

        session_key = hmac_sha256(master_key, device_nonce + gateway_nonce + shared_secret)

        auth_header = recv_exact(conn, 1)
        if auth_header[0] != CMD_AUTH:
            conn.sendall(bytes([CMD_AUTH_FAIL]))
            outcome = "bad_auth_msg"
            return

        received_tag = recv_exact(conn, TAG_LEN)
        expected_tag = hmac_sha256(session_key, b"AUTH_CONFIRM")

        if constant_time_compare(received_tag, expected_tag):
            conn.sendall(bytes([CMD_AUTH_OK]))
            outcome = "AUTH_OK"
        else:
            conn.sendall(bytes([CMD_AUTH_FAIL]))
            outcome = "AUTH_FAIL"

    except Exception as e:
        outcome = f"exception:{e}"

    finally:
        total_ms = (time.monotonic() - start_time) * 1000
        timestamp_iso = datetime.now().isoformat()

        log_writer.writerow([timestamp_iso, device_id, addr[0],
                              f"{total_ms:.3f}", f"{x25519_ms:.3f}", outcome])
        log_file.flush()
        print(f"[{timestamp_iso}] {device_id} ({addr[0]}) -> {outcome} "
              f"total={total_ms:.3f}ms  x25519={x25519_ms:.3f}ms")

        if device_id in DEVICE_ORDER:
            STATE.record_handshake(device_id)

        conn.close()


def run_handshake_server():
    log_file, log_writer = init_csv_log(
        HANDSHAKE_LOG_FILE,
        ["timestamp_iso", "device_id", "client_ip", "total_latency_ms", "x25519_latency_ms", "outcome"],
    )
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((HOST, HANDSHAKE_PORT))
        server.listen(5)
        print(f"[handshake] listening on {HOST}:{HANDSHAKE_PORT}")
        while True:
            conn, addr = server.accept()
            handle_handshake_client(conn, addr, log_writer, log_file)


# ---------------------------------------------------------------------------
# 2) Precompute marker server (port 5002) -- unchanged from precompute_marker_logger.py
def handle_marker_client(conn, addr, log_writer, log_file):
    try:
        header = recv_exact(conn, 2)
        marker_type, id_len = header[0], header[1]
        device_id = recv_exact(conn, id_len).decode()
        timestamp_iso = datetime.now().isoformat()
        marker_name = "START" if marker_type == MARKER_START else "END"
        log_writer.writerow([timestamp_iso, device_id, marker_name])
        log_file.flush()
    except Exception as e:
        print(f"[marker] error from {addr[0]}: {e}")
    finally:
        conn.close()


def run_marker_server():
    log_file, log_writer = init_csv_log(
        PRECOMPUTE_LOG_FILE, ["timestamp_iso", "device_id", "marker_type"]
    )
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((HOST, MARKER_PORT))
        server.listen(5)
        print(f"[marker]    listening on {HOST}:{MARKER_PORT}")
        while True:
            conn, addr = server.accept()
            handle_marker_client(conn, addr, log_writer, log_file)


# ---------------------------------------------------------------------------
# 3) Session-gate server (port 5003) -- NEW in v7. Each Pico connects right
#    after WiFi and blocks; we hold the socket open and only write the GO
#    byte to it when the orchestrator decides it's that device's turn.
def handle_gate_client(conn, addr):
    try:
        header = recv_exact(conn, 2)
        if header[0] != GATE_HELLO:
            conn.close()
            return
        id_len = header[1]
        device_id = recv_exact(conn, id_len).decode()
        if device_id not in DEVICE_ORDER:
            conn.close()
            return
        print(f"[gate]      {device_id} reported in from {addr[0]}, idling until its session")
        STATE.register_gate_socket(device_id, conn)
        # NOTE: deliberately not closing `conn` here -- it stays open,
        # held by STATE, until send_go() writes to it and closes it.
    except Exception as e:
        print(f"[gate] error from {addr[0]}: {e}")
        conn.close()


def run_gate_server():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((HOST, GATE_PORT))
        server.listen(5)
        print(f"[gate]      listening on {HOST}:{GATE_PORT}")
        while True:
            conn, addr = server.accept()
            # Each registration is quick; handle inline rather than spawning
            # a thread per connection (there are only ever two of these).
            handle_gate_client(conn, addr)


# ---------------------------------------------------------------------------
# 4) INA219 power polling -- continuous, logs power_log.csv in the same
#    schema used by every earlier version, and keeps STATE.latest_power
#    fresh for the LCDs.
def run_power_poller():
    i2c = busio.I2C(board.SCL, board.SDA)
    sensors = {}
    for device, addr in INA_ADDR.items():
        ina = INA219(i2c, addr=addr)
        ina.set_calibration_16V_400mA()
        sensors[device] = ina
        print(f"[power]     {device}: INA219 @ {hex(addr)}")

    log_file, log_writer = init_csv_log(
        POWER_LOG_FILE, ["timestamp_iso", "monotonic_s", "device", "voltage_v", "current_ma", "power_w"]
    )

    try:
        while True:
            now_mono = time.monotonic()
            now_iso = datetime.now().isoformat()
            for device, ina in sensors.items():
                voltage_v = ina.bus_voltage
                current_ma = ina.current
                power_w = ina.power
                STATE.update_power(device, current_ma, power_w, voltage_v)
                log_writer.writerow([now_iso, f"{now_mono:.6f}", device,
                                      f"{voltage_v:.4f}", f"{current_ma:.3f}", f"{power_w:.4f}"])
            log_file.flush()
            time.sleep(POWER_POLL_INTERVAL_SEC)
    finally:
        log_file.close()


# ---------------------------------------------------------------------------
# 5) The LCD dashboard / session orchestrator -- the actual state machine
#    described at the top of this file.
def _idle_message_for(device):
    p = STATE.get_power(device)
    return (f"{device} is connected.", f"Current power draw: {p['power_w']:.2f}")


def _analyzing_message_for(device):
    p = STATE.get_power(device)
    return (f"Analyzing handshakes on {device}", f"Real-time power draw: {p['power_w']:.2f}")


def _wait_for_connection(displays, device):
    """Block (while refreshing both LCDs with live idle power) until
    `device`'s measured current crosses the connected threshold."""
    while True:
        for d in DEVICE_ORDER:
            displays[d].set_message(*_idle_message_for(d))
        _pump_displays(displays, LCD_REFRESH_INTERVAL_SEC)
        if STATE.get_power(device)["current_ma"] >= CONNECTED_CURRENT_THRESHOLD_MA:
            return


def _pump_displays(displays, duration_sec):
    """Keep both LCDs scrolling/refreshing for `duration_sec`, without
    changing their messages. Returns after the duration elapses."""
    end = time.monotonic() + duration_sec
    while time.monotonic() < end:
        for d in displays.values():
            d.tick()
        time.sleep(LCD_REFRESH_INTERVAL_SEC)


def _pump_displays_live(displays, device, message_fn, until_fn):
    """Like _pump_displays, but re-renders `device`'s message every tick
    from `message_fn()` (for live power readouts) and returns as soon as
    `until_fn()` is True. The OTHER device's LCD keeps showing its idle
    readout the whole time."""
    other = [d for d in DEVICE_ORDER if d != device][0]
    while not until_fn():
        displays[device].set_message(*message_fn(device))
        displays[other].set_message(*_idle_message_for(other))
        for d in displays.values():
            d.tick()
        time.sleep(LCD_REFRESH_INTERVAL_SEC)


def _session_complete(device, baseline_count):
    """True once `device` has reached TARGET_HANDSHAKES new handshakes,
    or has gone quiet for SESSION_QUIET_TIMEOUT_SEC after starting."""
    count = STATE.get_handshake_count(device) - baseline_count
    if count >= TARGET_HANDSHAKES:
        return True
    last_ts = STATE.get_last_handshake_ts(device)
    if last_ts is not None and (time.monotonic() - last_ts) > SESSION_QUIET_TIMEOUT_SEC:
        print(f"[dashboard] {device}: no handshake activity for "
              f"{SESSION_QUIET_TIMEOUT_SEC}s after starting -- treating session as complete "
              f"({count}/{TARGET_HANDSHAKES} seen).")
        return True
    return False


def run_dashboard(displays):
    # --- Phase 0: wait for both boards to connect and show idle power ---
    print("[dashboard] waiting for both boards to connect...")
    for device in DEVICE_ORDER:
        _wait_for_connection(displays, device)
        print(f"[dashboard] {device} connected (current above threshold).")
    print("[dashboard] both boards connected -- holding idle display for "
          f"{CONNECT_HOLD_SEC}s before session #1.")
    _pump_displays(displays, CONNECT_HOLD_SEC)

    for session_num, device in enumerate(DEVICE_ORDER, start=1):
        baseline_count = STATE.get_handshake_count(device)

        # --- Announce + send GO ---
        print(f"[dashboard] session #{session_num}: sending GO to {device}")
        displays[device].set_message(
            f"Testing #{session_num} session about to begin.", f"{device} is active......"
        )
        STATE.send_go(device)
        _pump_displays(displays, ANNOUNCE_SEC)

        # --- Analyzing, live, until this device's batch completes ---
        print(f"[dashboard] session #{session_num}: showing live analysis for {device}")
        _pump_displays_live(
            displays, device, _analyzing_message_for,
            until_fn=lambda d=device, b=baseline_count: _session_complete(d, b),
        )

        # --- Session complete hold ---
        if session_num < len(DEVICE_ORDER):
            next_device = DEVICE_ORDER[session_num]
            displays[device].set_message(
                f"Testing #{session_num} session is complete.",
                f"Preparing for Testing session #{session_num + 1}",
            )
            print(f"[dashboard] session #{session_num} complete; "
                  f"{COMPLETE_HOLD_SEC}s hold before session #{session_num + 1}.")
            _pump_displays(displays, COMPLETE_HOLD_SEC)

    # --- Final message on both LCDs ---
    print("[dashboard] all sessions complete.")
    for d in DEVICE_ORDER:
        displays[d].set_message("Testing session completed", "")
    _pump_displays(displays, COMPLETE_HOLD_SEC)
    print("[dashboard] done -- leaving final message on screen. Ctrl+C to exit.")
    while True:
        for d in displays.values():
            d.tick()
        time.sleep(LCD_REFRESH_INTERVAL_SEC)


# ---------------------------------------------------------------------------
def main():
    lcd1 = open_lcd(I2C_BUS_NUM, LCD1_ADDR)
    lcd2 = open_lcd(I2C_BUS_NUM, LCD2_ADDR)
    displays = {
        DEVICE_ORDER[0]: LCDStatusDisplay(lcd1),
        DEVICE_ORDER[1]: LCDStatusDisplay(lcd2),
    }
    for d in DEVICE_ORDER:
        displays[d].set_message("Waiting for board", "to connect...")

    threads = [
        threading.Thread(target=run_handshake_server, daemon=True),
        threading.Thread(target=run_marker_server, daemon=True),
        threading.Thread(target=run_gate_server, daemon=True),
        threading.Thread(target=run_power_poller, daemon=True),
    ]
    for t in threads:
        t.start()

    time.sleep(1.0)  # let the servers finish binding before the dashboard needs them
    try:
        run_dashboard(displays)
    except KeyboardInterrupt:
        print("\nShutting down.")


if __name__ == "__main__":
    main()
