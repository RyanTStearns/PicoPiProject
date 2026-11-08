#!/usr/bin/env python3
"""
voltage_delta_monitor.py
--------------------------
Standalone live diagnostic tool: establishes an idle baseline for each
INA219, then continuously reports the live voltage/current delta
(active - idle) as readings come in. Useful for wiring diagnosis --
run this while probing connections with a multimeter, or while
manually triggering a handshake, to see the delta update in real time
without needing a full batch run or CSV analysis afterward.

Requires: pip install adafruit-circuitpython-ina219 adafruit-blinka

Run:
    python3 voltage_delta_monitor.py
    (keep devices idle for the first few seconds to establish baseline)
    (Ctrl+C to stop)
"""

import time
import board
import busio
from adafruit_ina219 import INA219

DEVICES = [
    {"name": "Pico2W-1", "ina_addr": 0x40},
    {"name": "Pico2W-2", "ina_addr": 0x41},
]

BASELINE_DURATION_SEC = 5
POLL_INTERVAL_SEC = 0.2


def init_devices(i2c):
    for dev in DEVICES:
        ina = INA219(i2c, addr=dev["ina_addr"])
        ina.set_calibration_16V_400mA()
        dev["ina"] = ina
        print(f"Initialized {dev['name']}: INA219 @ {hex(dev['ina_addr'])}")


def read(dev):
    ina = dev["ina"]
    return {
        "voltage_v": ina.bus_voltage,
        "current_ma": ina.current,
        "power_w": ina.power,
    }


def establish_baseline(devices):
    print(f"\nEstablishing baseline over {BASELINE_DURATION_SEC}s -- "
          f"keep devices IDLE now...\n")

    samples = {dev["name"]: {"voltage_v": [], "current_ma": [], "power_w": []}
               for dev in devices}

    start = time.time()
    while time.time() - start < BASELINE_DURATION_SEC:
        for dev in devices:
            r = read(dev)
            samples[dev["name"]]["voltage_v"].append(r["voltage_v"])
            samples[dev["name"]]["current_ma"].append(r["current_ma"])
            samples[dev["name"]]["power_w"].append(r["power_w"])
        time.sleep(POLL_INTERVAL_SEC)

    baseline = {}
    for dev in devices:
        name = dev["name"]
        v = samples[name]["voltage_v"]
        i = samples[name]["current_ma"]
        p = samples[name]["power_w"]
        baseline[name] = {
            "voltage_v": sum(v) / len(v),
            "current_ma": sum(i) / len(i),
            "power_w": sum(p) / len(p),
        }
        print(f"  {name} baseline: "
              f"{baseline[name]['voltage_v']:.3f} V, "
              f"{baseline[name]['current_ma']:.2f} mA, "
              f"{baseline[name]['power_w']:.4f} W")

    return baseline


def main():
    i2c = busio.I2C(board.SCL, board.SDA)
    init_devices(i2c)

    baseline = establish_baseline(DEVICES)

    print("\nBaseline set. Now showing LIVE delta (active - idle) readings.")
    print("Trigger a handshake, probe wiring, etc. -- watch deltas update.")
    print("Press Ctrl+C to stop.\n")

    try:
        while True:
            line_parts = []
            for dev in DEVICES:
                name = dev["name"]
                r = read(dev)
                base = baseline[name]

                v_delta = r["voltage_v"] - base["voltage_v"]
                i_delta = r["current_ma"] - base["current_ma"]
                p_delta = r["power_w"] - base["power_w"]

                line_parts.append(
                    f"{name}: V={r['voltage_v']:.3f} (Δ{v_delta:+.3f})  "
                    f"I={r['current_ma']:6.2f}mA (Δ{i_delta:+.2f})  "
                    f"P={r['power_w']:.4f}W (Δ{p_delta:+.4f})"
                )

            print(" | ".join(line_parts))
            time.sleep(POLL_INTERVAL_SEC)

    except KeyboardInterrupt:
        print("\nStopped.")


if __name__ == "__main__":
    main()
