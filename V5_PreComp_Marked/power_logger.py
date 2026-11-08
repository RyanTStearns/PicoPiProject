#!/usr/bin/env python3
"""
Power Logger
-------------
Continuously polls both INA219 sensors as fast as the I2C bus allows and
logs timestamped current/voltage/power readings to a CSV file. Run this
in its own terminal, started BEFORE you kick off a protocol batch run on
either Pico, so you capture power draw across the entire test window.

Uses the gateway's own clock for every reading -- the same clock your
protocol server timestamps handshakes with -- so the two logs can be
joined afterward on a shared timeline without any cross-device clock
sync issues.

Requires: pip install adafruit-circuitpython-ina219 adafruit-blinka

Run:
    python3 power_logger.py
    (Ctrl+C to stop)
"""

import time
import csv
import board
import busio
from datetime import datetime
from adafruit_ina219 import INA219

LOG_FILE = "power_log.csv"

DEVICES = [
    {"name": "Pico2W-1", "ina_addr": 0x40},
    {"name": "Pico2W-2", "ina_addr": 0x41},
]


def init_devices(i2c):
    for dev in DEVICES:
        ina = INA219(i2c, addr=dev["ina_addr"])
        # Tighten the calibration range for small IoT-scale currents
        # (tens of mA) rather than the default 32V/2A range, for better
        # resolution.
        ina.set_calibration_16V_400mA()
        dev["ina"] = ina
        print(f"Initialized {dev['name']}: INA219 @ {hex(dev['ina_addr'])}")


def main():
    i2c = busio.I2C(board.SCL, board.SDA)
    init_devices(i2c)

    file_exists = False
    try:
        with open(LOG_FILE, "r"):
            file_exists = True
    except FileNotFoundError:
        pass

    log_file = open(LOG_FILE, "a", newline="")
    writer = csv.writer(log_file)
    if not file_exists:
        writer.writerow(["timestamp_iso", "monotonic_s", "device", "voltage_v", "current_ma", "power_w"])

    print(f"\nLogging power to {LOG_FILE}. Press Ctrl+C to stop.\n")

    sample_count = 0
    start_wall = time.time()

    try:
        while True:
            for dev in DEVICES:
                ina = dev["ina"]
                ts_iso = datetime.now().isoformat()
                ts_mono = time.monotonic()
                voltage = ina.bus_voltage
                current_ma = ina.current
                power_w = ina.power

                writer.writerow([
                    ts_iso, f"{ts_mono:.6f}", dev["name"],
                    f"{voltage:.4f}", f"{current_ma:.3f}", f"{power_w:.4f}"
                ])
                sample_count += 1

            log_file.flush()

            # Print a periodic status line (not every sample, to avoid
            # flooding the console) so you can confirm it's alive.
            if sample_count % 100 == 0:
                elapsed = time.time() - start_wall
                rate = sample_count / elapsed if elapsed > 0 else 0
                print(f"{sample_count} samples logged "
                      f"({rate:.1f} samples/sec combined)")

    except KeyboardInterrupt:
        print(f"\nStopped. {sample_count} total samples logged to {LOG_FILE}.")
    finally:
        log_file.close()


if __name__ == "__main__":
    main()
