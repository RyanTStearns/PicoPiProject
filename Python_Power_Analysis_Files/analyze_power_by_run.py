#!/usr/bin/env python3
"""
analyze_power_by_run.py
--------------------------
Companion to pico_protocol_v6_standalone: one long logging session now
holds several runs per Pico, separated by a long idle gap. This script
finds those runs and applies the SAME three-window analysis as
analyze_power_three_window.py to each run separately, then reports the
mean and standard deviation across runs.

How runs are found (per device):
  Successful handshakes are sorted by time. Whenever two consecutive
  handshakes are more than --gap seconds apart, a new run starts.
  Handshakes inside a run are ~2.4 s apart and the Pico idles 60 s
  between runs (RUN_GAP_SEC), so the default of 30 s separates them.

What counts as each run's time span:
  From the start of its first handshake to the end of its last
  precompute window. "True idle" is therefore the idle time BETWEEN
  handshakes inside the run. The long gaps between runs (where the Pico
  writes its log to flash) and the lead-in before run 1 are excluded.

Requires: pip install pandas
Requires analyze_power_three_window.py in the same directory.

Run:
    python3 analyze_power_by_run.py handshake_log_forward_secret.csv precompute_log.csv power_log.csv
    python3 analyze_power_by_run.py <handshake> <precompute> <power> --gap 30 --csv per_run.csv
"""

import argparse
import sys
import pandas as pd

from analyze_power_three_window import load_logs, analyze

METRICS = [
    ("idle_current_ma", "true idle avg current (mA)"),
    ("idle_power_w", "true idle avg power (W)"),
    ("handshake_current_ma", "handshake avg current (mA)"),
    ("handshake_power_w", "handshake avg power (W)"),
    ("handshake_energy_mj", "energy per handshake (mJ)"),
    ("precompute_current_ma", "precompute avg current (mA)"),
    ("precompute_power_w", "precompute avg power (W)"),
    ("precompute_energy_mj", "energy per precompute (mJ)"),
    ("cycle_energy_mj", "energy per full cycle (mJ)"),
]


def find_runs(device_handshakes, device_markers, gap_s):
    """Return a list of (run_start, run_end) for one device."""
    hs = device_handshakes.sort_values("end_time")
    if hs.empty:
        return []

    gap = pd.Timedelta(seconds=gap_s)
    run_id = (hs["end_time"].diff() > gap).cumsum()

    runs = []
    for _, group in hs.groupby(run_id):
        run_start = group["start_time"].min()
        run_end = group["end_time"].max()
        # Extend to the last precompute marker that belongs to this run
        # (the END marker after the final handshake).
        if not device_markers.empty:
            tail = device_markers[
                (device_markers["timestamp_iso"] > run_end)
                & (device_markers["timestamp_iso"] <= run_end + gap / 2)
            ]
            if not tail.empty:
                run_end = tail["timestamp_iso"].max()
        runs.append((run_start, run_end))
    return runs


def flatten(result):
    row = {
        "idle_current_ma": result["idle"]["avg_current_ma"],
        "idle_power_w": result["idle"]["avg_power_w"],
    }
    if "handshake" in result:
        h = result["handshake"]
        row["handshake_events"] = h["num_windows"]
        row["handshake_current_ma"] = h["avg_current_ma"]
        row["handshake_power_w"] = h["avg_power_w"]
        row["handshake_energy_mj"] = h["energy_per_event_mj"]
    if "precompute" in result:
        p = result["precompute"]
        row["precompute_events"] = p["num_windows"]
        row["precompute_current_ma"] = p["avg_current_ma"]
        row["precompute_power_w"] = p["avg_power_w"]
        row["precompute_energy_mj"] = p["energy_per_event_mj"]
    if "total_energy_per_cycle_mj" in result:
        row["cycle_energy_mj"] = result["total_energy_per_cycle_mj"]
    return row


def analyze_by_run(handshakes, precompute, power, gap_s):
    rows = []
    for device in sorted(handshakes["device_id"].unique()):
        dev_hs = handshakes[handshakes["device_id"] == device]
        dev_markers = precompute[precompute["device_id"] == device]
        dev_power = power[power["device"] == device]

        for run_num, (start, end) in enumerate(find_runs(dev_hs, dev_markers, gap_s), 1):
            run_hs = dev_hs[(dev_hs["start_time"] >= start) & (dev_hs["end_time"] <= end)]
            run_markers = dev_markers[
                (dev_markers["timestamp_iso"] >= start)
                & (dev_markers["timestamp_iso"] <= end)
            ]
            run_power = dev_power[
                (dev_power["timestamp_iso"] >= start)
                & (dev_power["timestamp_iso"] <= end)
            ]
            if run_power.empty:
                print(f"WARNING: no power samples for {device} run {run_num}, skipping.")
                continue

            result = analyze(run_hs, run_markers, run_power)
            if not result:
                continue

            row = {
                "device": device,
                "run": run_num,
                "run_start": start.isoformat(),
                "run_end": end.isoformat(),
                "duration_s": (end - start).total_seconds(),
            }
            row.update(flatten(result[0]))
            rows.append(row)

    return pd.DataFrame(rows)


def print_report(table, gap_s):
    print("\n" + "=" * 70)
    print("THREE-WINDOW POWER ANALYSIS -- PER RUN")
    print(f"(runs split wherever handshakes are more than {gap_s:g} s apart)")
    print("=" * 70)

    for device, dev in table.groupby("device"):
        print(f"\nDevice: {device}  --  {len(dev)} run(s) found")
        for _, r in dev.iterrows():
            print(f"\n  RUN {int(r['run'])}  {r['run_start']}  ->  {r['run_end']}"
                  f"  ({r['duration_s']:.1f} s)")
            print(f"    TRUE IDLE:   {r['idle_current_ma']:.2f} mA, {r['idle_power_w']:.4f} W")
            if "handshake_energy_mj" in r and pd.notna(r["handshake_energy_mj"]):
                print(f"    HANDSHAKE ({int(r['handshake_events'])} events): "
                      f"{r['handshake_current_ma']:.2f} mA, {r['handshake_power_w']:.4f} W, "
                      f"{r['handshake_energy_mj']:.3f} mJ each")
            if "precompute_energy_mj" in r and pd.notna(r["precompute_energy_mj"]):
                print(f"    PRECOMPUTE ({int(r['precompute_events'])} events): "
                      f"{r['precompute_current_ma']:.2f} mA, {r['precompute_power_w']:.4f} W, "
                      f"{r['precompute_energy_mj']:.3f} mJ each")
            if "cycle_energy_mj" in r and pd.notna(r["cycle_energy_mj"]):
                print(f"    FULL CYCLE:  {r['cycle_energy_mj']:.3f} mJ")

        print(f"\n  ACROSS {len(dev)} RUNS (mean +/- sample std dev):")
        for key, label in METRICS:
            if key in dev and dev[key].notna().any():
                sd = dev[key].std() if dev[key].count() > 1 else float("nan")
                print(f"    {label:<32} {dev[key].mean():10.4f} +/- {sd:.4f}")

    print("\n" + "=" * 70)


def main():
    parser = argparse.ArgumentParser(description="Per-run three-window power analysis")
    parser.add_argument("handshake_log")
    parser.add_argument("precompute_log")
    parser.add_argument("power_log")
    parser.add_argument("--gap", type=float, default=30.0,
                        help="seconds between handshakes that starts a new run (default 30)")
    parser.add_argument("--csv", help="also write the per-run table to this CSV file")
    args = parser.parse_args()

    handshakes, precompute, power = load_logs(
        args.handshake_log, args.precompute_log, args.power_log
    )
    table = analyze_by_run(handshakes, precompute, power, args.gap)

    if table.empty:
        print("No runs found -- check that the logs contain AUTH_OK handshakes.")
        sys.exit(1)

    print_report(table, args.gap)

    if args.csv:
        table.to_csv(args.csv, index=False)
        print(f"Per-run table written to {args.csv}")


if __name__ == "__main__":
    main()
