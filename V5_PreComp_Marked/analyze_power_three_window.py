#!/usr/bin/env python3
"""
analyze_power_three_window.py
---------------------------------
Splits power data into THREE windows instead of two:
  1. Handshake critical path (from handshake_log, start=end-latency)
  2. Precompute window (from precompute_log, START marker to END marker)
  3. True idle (everything else)

This avoids the measurement artifact where precomputed keygen work
silently gets counted as "idle" power, which otherwise makes
precomputation look like it reduces total energy (it doesn't -- it
only moves *when* the energy is spent).

Requires: pip install pandas

Run:
    python3 analyze_power_three_window.py handshake_log_forward_secret.csv precompute_log.csv power_log.csv
"""

import sys
import pandas as pd


def load_logs(handshake_path, precompute_path, power_path):
    def load_ts(path, col="timestamp_iso"):
        df = pd.read_csv(path)
        df[col] = pd.to_datetime(df[col], errors="coerce")
        bad = df[col].isna().sum()
        if bad:
            print(f"WARNING: dropping {bad} unparseable row(s) from {path}")
            df = df.dropna(subset=[col])
        return df

    handshakes = load_ts(handshake_path)
    precompute = load_ts(precompute_path)
    power = load_ts(power_path)

    handshakes = handshakes[handshakes["outcome"] == "AUTH_OK"].copy()
    handshakes["end_time"] = handshakes["timestamp_iso"]
    handshakes["start_time"] = handshakes["end_time"] - pd.to_timedelta(
        handshakes["total_latency_ms"], unit="ms"
    )

    return handshakes, precompute, power


def pair_precompute_windows(precompute, device):
    """Pair up consecutive START/END markers for one device into
    (start_time, end_time) windows."""
    dev_markers = precompute[precompute["device_id"] == device].sort_values(
        "timestamp_iso"
    )
    windows = []
    pending_start = None
    for _, row in dev_markers.iterrows():
        if row["marker_type"] == "START":
            pending_start = row["timestamp_iso"]
        elif row["marker_type"] == "END" and pending_start is not None:
            windows.append((pending_start, row["timestamp_iso"]))
            pending_start = None
    return windows


def mask_for_windows(power_times, windows):
    mask = pd.Series(False, index=power_times.index)
    for start, end in windows:
        mask |= (power_times >= start) & (power_times <= end)
    return mask


def analyze(handshakes, precompute, power):
    results = []

    all_devices = set(handshakes["device_id"].unique()) | set(
        precompute["device_id"].unique() if not precompute.empty else []
    )

    for device in all_devices:
        device_handshakes = handshakes[handshakes["device_id"] == device]
        device_power = power[power["device"] == device].copy()

        if device_power.empty:
            print(f"WARNING: no power data for {device}, skipping.")
            continue

        handshake_windows = [
            (row["start_time"], row["end_time"])
            for _, row in device_handshakes.iterrows()
        ]
        precompute_windows = pair_precompute_windows(precompute, device)

        handshake_mask = mask_for_windows(device_power["timestamp_iso"], handshake_windows)
        precompute_mask = mask_for_windows(device_power["timestamp_iso"], precompute_windows)
        # True idle = neither handshake nor precompute
        idle_mask = ~handshake_mask & ~precompute_mask

        def window_stats(mask, windows):
            subset = device_power[mask]
            if subset.empty:
                return None
            avg_current = subset["current_ma"].mean()
            avg_power = subset["power_w"].mean()
            total_duration_s = sum(
                (end - start).total_seconds() for start, end in windows
            ) if windows else None
            return {
                "avg_current_ma": avg_current,
                "avg_power_w": avg_power,
                "total_duration_s": total_duration_s,
                "num_windows": len(windows) if windows else None,
            }

        idle_stats = window_stats(idle_mask, None)
        handshake_stats = window_stats(handshake_mask, handshake_windows)
        precompute_stats = window_stats(precompute_mask, precompute_windows)

        if idle_stats is None:
            print(f"WARNING: no true-idle samples found for {device}.")
            continue

        result = {"device": device, "idle": idle_stats}

        if handshake_stats:
            handshake_energy_mj = (
                handshake_stats["avg_power_w"] * handshake_stats["total_duration_s"] * 1000
                / handshake_stats["num_windows"]
            )
            handshake_stats["energy_per_event_mj"] = handshake_energy_mj
            result["handshake"] = handshake_stats

        if precompute_stats:
            precompute_energy_mj = (
                precompute_stats["avg_power_w"] * precompute_stats["total_duration_s"] * 1000
                / precompute_stats["num_windows"]
            )
            precompute_stats["energy_per_event_mj"] = precompute_energy_mj
            result["precompute"] = precompute_stats

        if handshake_stats and precompute_stats:
            result["total_energy_per_cycle_mj"] = (
                handshake_stats["energy_per_event_mj"]
                + precompute_stats["energy_per_event_mj"]
            )

        results.append(result)

    return results


def print_report(results):
    print("\n" + "=" * 70)
    print("THREE-WINDOW POWER ANALYSIS REPORT")
    print("=" * 70)

    for r in results:
        print(f"\nDevice: {r['device']}")
        print(f"  TRUE IDLE:")
        print(f"    avg current: {r['idle']['avg_current_ma']:.2f} mA, "
              f"avg power: {r['idle']['avg_power_w']:.4f} W")

        if "handshake" in r:
            h = r["handshake"]
            print(f"  HANDSHAKE CRITICAL PATH ({h['num_windows']} events):")
            print(f"    avg current: {h['avg_current_ma']:.2f} mA, "
                  f"avg power: {h['avg_power_w']:.4f} W")
            print(f"    energy per handshake: {h['energy_per_event_mj']:.3f} mJ")

        if "precompute" in r:
            p = r["precompute"]
            print(f"  PRECOMPUTE WINDOW ({p['num_windows']} events):")
            print(f"    avg current: {p['avg_current_ma']:.2f} mA, "
                  f"avg power: {p['avg_power_w']:.4f} W")
            print(f"    energy per precompute: {p['energy_per_event_mj']:.3f} mJ")

        if "total_energy_per_cycle_mj" in r:
            print(f"  TOTAL ENERGY PER FULL CYCLE (handshake + precompute): "
                  f"{r['total_energy_per_cycle_mj']:.3f} mJ")

    print("\n" + "=" * 70)


if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: python3 analyze_power_three_window.py "
              "<handshake_log.csv> <precompute_log.csv> <power_log.csv>")
        sys.exit(1)

    handshakes, precompute, power = load_logs(sys.argv[1], sys.argv[2], sys.argv[3])
    results = analyze(handshakes, precompute, power)
    print_report(results)
