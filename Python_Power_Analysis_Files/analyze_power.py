#!/usr/bin/env python3
"""
analyze_power.py
------------------
Correlates a handshake log (original or forward-secret) with the power
log captured during the same session, and reports:
  - Idle baseline current/power per device
  - Average current/power DURING each handshake window
  - Estimated energy (in millijoules) consumed per handshake

Both logs must share the same gateway clock (they do, since both are
timestamped by gateway_protocol_v*.py and power_logger.py running on
the same machine during the same session).

Requires: pip install pandas

Run:
    python3 analyze_power.py handshake_log_forward_secret.csv power_log.csv
    python3 analyze_power.py handshake_log_original.csv power_log.csv
"""

import sys
import pandas as pd


def load_logs(handshake_path, power_path):
    # Load as plain strings first, then explicitly coerce to datetimes.
    # This is more robust than read_csv's parse_dates when a file has a
    # malformed trailing row (e.g. truncated mid-write by a Ctrl+C), which
    # can otherwise cause the whole column to silently stay as text.
    handshakes = pd.read_csv(handshake_path)
    power = pd.read_csv(power_path)

    handshakes["timestamp_iso"] = pd.to_datetime(
        handshakes["timestamp_iso"], errors="coerce"
    )
    power["timestamp_iso"] = pd.to_datetime(
        power["timestamp_iso"], errors="coerce"
    )

    bad_handshake_rows = handshakes["timestamp_iso"].isna().sum()
    bad_power_rows = power["timestamp_iso"].isna().sum()

    if bad_handshake_rows:
        print(f"WARNING: dropping {bad_handshake_rows} unparseable row(s) "
              f"from {handshake_path}")
        handshakes = handshakes.dropna(subset=["timestamp_iso"])
    if bad_power_rows:
        print(f"WARNING: dropping {bad_power_rows} unparseable row(s) "
              f"from {power_path} (likely a truncated final write)")
        power = power.dropna(subset=["timestamp_iso"])

    return handshakes, power


def analyze(handshakes, power):
    # Only look at successful handshakes -- failed ones don't represent
    # real protocol cost.
    handshakes = handshakes[handshakes["outcome"] == "AUTH_OK"].copy()

    # Different protocol versions log the latency column under different
    # names (v3: "latency_ms", v4: "total_latency_ms") -- detect which one
    # is present rather than assuming.
    if "total_latency_ms" in handshakes.columns:
        latency_col = "total_latency_ms"
    elif "latency_ms" in handshakes.columns:
        latency_col = "latency_ms"
    else:
        raise KeyError(
            "Could not find a latency column in this handshake log "
            "(expected 'latency_ms' or 'total_latency_ms')."
        )

    # Handshake end time is the logged timestamp; start time is end minus
    # the recorded latency.
    handshakes["end_time"] = handshakes["timestamp_iso"]
    handshakes["start_time"] = handshakes["end_time"] - pd.to_timedelta(
        handshakes[latency_col], unit="ms"
    )
    handshakes["total_latency_ms"] = handshakes[latency_col]

    results = []

    for device in handshakes["device_id"].unique():
        device_handshakes = handshakes[handshakes["device_id"] == device]
        device_power = power[power["device"] == device].copy()

        if device_power.empty:
            print(f"WARNING: no power data found for {device}, skipping.")
            continue

        # Idle baseline: power samples NOT inside any handshake window.
        in_any_window = pd.Series(False, index=device_power.index)
        for _, hs in device_handshakes.iterrows():
            mask = (device_power["timestamp_iso"] >= hs["start_time"]) & (
                device_power["timestamp_iso"] <= hs["end_time"]
            )
            in_any_window |= mask

        idle_power = device_power[~in_any_window]
        idle_current_avg = idle_power["current_ma"].mean()
        idle_power_avg = idle_power["power_w"].mean()

        # Per-handshake stats
        handshake_currents = []
        handshake_powers = []
        handshake_energies_mj = []

        for _, hs in device_handshakes.iterrows():
            window = device_power[
                (device_power["timestamp_iso"] >= hs["start_time"])
                & (device_power["timestamp_iso"] <= hs["end_time"])
            ]
            if window.empty:
                continue

            avg_current = window["current_ma"].mean()
            avg_power = window["power_w"].mean()
            duration_s = hs["total_latency_ms"] / 1000.0
            energy_mj = avg_power * duration_s * 1000  # W * s * 1000 = mJ

            handshake_currents.append(avg_current)
            handshake_powers.append(avg_power)
            handshake_energies_mj.append(energy_mj)

        if not handshake_currents:
            # Fall back to block-level ("burst") averaging: individual
            # handshakes were too short for any power sample to land
            # inside them, so instead treat the ENTIRE span from the
            # first handshake's start to the last handshake's end as one
            # continuous active block. This only gives a meaningful result
            # if handshakes were run back-to-back with little/no gap
            # (e.g. DELAY_BETWEEN_SEC = 0), so the device was continuously
            # active for that whole span.
            block_start = device_handshakes["start_time"].min()
            block_end = device_handshakes["end_time"].max()
            block_power = device_power[
                (device_power["timestamp_iso"] >= block_start)
                & (device_power["timestamp_iso"] <= block_end)
            ]

            if block_power.empty:
                print(f"WARNING: no power samples fell inside the {device} "
                      f"burst window either -- check that power_logger.py "
                      f"was actually running during this batch.")
                continue

            block_duration_s = (block_end - block_start).total_seconds()
            num_handshakes = len(device_handshakes)
            avg_current = block_power["current_ma"].mean()
            avg_power = block_power["power_w"].mean()
            total_energy_mj = avg_power * block_duration_s * 1000
            energy_per_handshake_mj = (
                total_energy_mj / num_handshakes if num_handshakes else 0
            )

            print(f"NOTE: {device} -- no individual handshake window had a "
                  f"power sample (handshakes shorter than sampling "
                  f"interval). Falling back to BLOCK-LEVEL average over "
                  f"the full {block_duration_s:.2f}s burst "
                  f"({num_handshakes} handshakes, {len(block_power)} power "
                  f"samples). This assumes handshakes ran back-to-back "
                  f"with minimal idle gaps in between.")

            results.append({
                "device": device,
                "num_handshakes": num_handshakes,
                "idle_current_ma": idle_current_avg,
                "idle_power_w": idle_power_avg,
                "handshake_current_ma_avg": avg_current,
                "handshake_power_w_avg": avg_power,
                "handshake_energy_mj_avg": energy_per_handshake_mj,
                "measurement_mode": "block-level (burst)",
            })
            continue

        results.append({
            "device": device,
            "num_handshakes": len(handshake_currents),
            "idle_current_ma": idle_current_avg,
            "idle_power_w": idle_power_avg,
            "handshake_current_ma_avg": sum(handshake_currents) / len(handshake_currents),
            "handshake_power_w_avg": sum(handshake_powers) / len(handshake_powers),
            "handshake_energy_mj_avg": sum(handshake_energies_mj) / len(handshake_energies_mj),
            "measurement_mode": "per-handshake",
        })

    return results


def print_report(results):
    print("\n" + "=" * 70)
    print("POWER ANALYSIS REPORT")
    print("=" * 70)

    for r in results:
        mode = r.get("measurement_mode", "per-handshake")
        print(f"\nDevice: {r['device']}  ({r['num_handshakes']} handshakes analyzed, "
              f"mode: {mode})")
        print(f"  Idle current:           {r['idle_current_ma']:.2f} mA")
        print(f"  Idle power:             {r['idle_power_w']:.4f} W")
        print(f"  Handshake avg current:  {r['handshake_current_ma_avg']:.2f} mA")
        print(f"  Handshake avg power:    {r['handshake_power_w_avg']:.4f} W")
        current_delta = r['handshake_current_ma_avg'] - r['idle_current_ma']
        print(f"  Current delta (active - idle): {current_delta:+.2f} mA")
        print(f"  Estimated energy per handshake: {r['handshake_energy_mj_avg']:.3f} mJ")

    print("\n" + "=" * 70)


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python3 analyze_power.py <handshake_log.csv> <power_log.csv>")
        sys.exit(1)

    handshakes, power = load_logs(sys.argv[1], sys.argv[2])
    results = analyze(handshakes, power)
    print_report(results)
