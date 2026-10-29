"""Analyse the 16 Mininet experiment runs (detection + blocking timings).

Usage (from the repository root):
    python3 analysis/analyze_results.py

Inputs (inside --data, default results/):
    block_events.csv                       block lifecycle events (Person 2)
    detection_log_<run_id>.csv             monitor logs, one per run
    pre-experiment/detection_log.csv       (optional) log before run 1

Outputs (inside --out, default results/):
    results_per_run.csv, results_summary.csv,
    fig_detection_time.png, fig_blocking_time.png

Note on the logs: for trials 1-3 each detection log is a cumulative snapshot
(it contains everything logged since the previous snapshot). Per-run rows are
recovered by removing the previous snapshot as a prefix. Trial 4 logs are
already per-run. Rows with timestamps below 1e9 are replay-test leftovers and
are ignored. Client-side success rate / PONG latency were not recorded for
these runs, so they are NOT computed here.
"""
import argparse
import csv
import os
import statistics as st
from collections import defaultdict
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

DEFAULT_DIR = Path(__file__).resolve().parent.parent / "results"
LEGIT_IP = "10.0.0.1"
ATTACKER_IP = "10.0.0.2"
CONDITIONS = ["baseline", "protected"]
SCENARIOS = ["normal_only", "normal_plus_attack"]
TRIALS = [1, 2, 3, 4]
FIRST_RUN = "baseline_normal_only_t1"


def read_csv(path):
    with open(path, newline="") as f:
        return list(csv.DictReader(f))


def real_rows(rows):
    return [r for r in rows if float(r["epoch_time"]) >= 1e9]


def split_runs(data):
    """Return {run_id: own_rows} recovered from the cumulative snapshots."""
    evidence = data
    # run order inside each trial, as confirmed by Person 2
    order = [f"{c}_{s}_t{t}" for t in TRIALS for (c, s) in
             [("baseline", "normal_only"), ("protected", "normal_only"),
              ("baseline", "normal_plus_attack"), ("protected", "normal_plus_attack")]]
    backup = os.path.join(data, "pre-experiment", "detection_log.csv")
    prev = read_csv(backup) if os.path.exists(backup) else []
    runs, notes = {}, {}
    for run_id in order:
        rows = read_csv(os.path.join(evidence, f"detection_log_{run_id}.csv"))
        if prev and rows[:len(prev)] == prev:
            own = rows[len(prev):]
        else:
            own = rows                      # standalone (already per-run)
        if run_id == FIRST_RUN:
            own = [r for r in own if r["source_ip"] == LEGIT_IP]
            notes[run_id] = "log shared with pre-experiment test rows; attacker rows excluded"
        runs[run_id] = real_rows(own)
        prev = rows
    return order, runs, notes


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default=str(DEFAULT_DIR))
    ap.add_argument("--out", default=str(DEFAULT_DIR))
    args = ap.parse_args()
    os.makedirs(args.out, exist_ok=True)

    blocks = defaultdict(dict)
    for r in read_csv(os.path.join(args.data, "block_events.csv")):
        blocks[r["run_id"]][r["event"]] = float(r["epoch_time"])

    order, runs, notes = split_runs(args.data)
    table = []
    for run_id in order:
        cond, rest = run_id.split("_", 1)
        scen, trial = rest.rsplit("_t", 1)
        rows = runs[run_id]
        legit = [r for r in rows if r["event"] == "connection" and r["source_ip"] == LEGIT_IP]
        att = [r for r in rows if r["event"] == "connection" and r["source_ip"] == ATTACKER_IP]
        alerts = [r for r in rows if r["event"] == "alert"]
        legit_flagged = any(r["source_ip"] == LEGIT_IP for r in alerts)
        row = {"run_id": run_id, "condition": cond, "scenario": scen, "trial": int(trial),
               "legit_connections": len(legit), "attacker_connections": len(att),
               "alert_raised": bool(alerts), "legit_host_flagged": legit_flagged,
               "attacker_burst_span_ms": "", "detection_ms": "", "block_requested": False,
               "alert_to_request_ms": "", "request_to_drop_s": "",
               "first_attack_conn_to_drop_s": "", "drop_to_removed_s": "", "note": notes.get(run_id, "")}
        if att:
            t = [float(r["epoch_time"]) for r in att]
            row["attacker_burst_span_ms"] = round((max(t) - min(t)) * 1000, 2)
        if alerts:
            a = alerts[0]
            alert_t, first_t = float(a["epoch_time"]), float(a["first_in_window"])
            row["detection_ms"] = round((alert_t - first_t) * 1000, 3)
            b = blocks.get(run_id)
            if b and {"block_requested", "drop_installed", "block_removed"} <= set(b):
                row["block_requested"] = True
                row["alert_to_request_ms"] = round((b["block_requested"] - alert_t) * 1000, 2)
                row["request_to_drop_s"] = round(b["drop_installed"] - b["block_requested"], 3)
                row["first_attack_conn_to_drop_s"] = round(b["drop_installed"] - first_t, 3)
                row["drop_to_removed_s"] = round(b["block_removed"] - b["drop_installed"], 2)
        table.append(row)

    cols = list(table[0].keys())
    with open(os.path.join(args.out, "results_per_run.csv"), "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=cols)
        w.writeheader()
        w.writerows(table)

    def vals(rows, key):
        return [float(r[key]) for r in rows if r[key] != ""]

    attack = [r for r in table if r["scenario"] == "normal_plus_attack"]
    base_att = [r for r in attack if r["condition"] == "baseline"]
    prot_att = [r for r in attack if r["condition"] == "protected"]
    normal = [r for r in table if r["scenario"] == "normal_only"]
    summary = []

    def add(metric, group, v, unit):
        if v:
            summary.append([metric, group, len(v), round(st.median(v), 3), round(min(v), 3), round(max(v), 3), unit])

    add("detection time", "baseline, normal+attack", vals(base_att, "detection_ms"), "ms")
    add("detection time", "protected, normal+attack", vals(prot_att, "detection_ms"), "ms")
    add("detection time", "all attack runs", vals(attack, "detection_ms"), "ms")
    add("attacker burst span (all 7 connections)", "all attack runs", vals(attack, "attacker_burst_span_ms"), "ms")
    add("alert to block request", "protected, normal+attack", vals(prot_att, "alert_to_request_ms"), "ms")
    add("block request to DROP installed", "protected, normal+attack", vals(prot_att, "request_to_drop_s"), "s")
    add("first attack connection to DROP installed", "protected, normal+attack", vals(prot_att, "first_attack_conn_to_drop_s"), "s")
    add("DROP installed to removed", "protected, normal+attack", vals(prot_att, "drop_to_removed_s"), "s")
    n_flag = sum(1 for r in table if r["legit_host_flagged"])
    n_false_block = sum(1 for r in normal if r["block_requested"])
    n_base_block = sum(1 for r in base_att if r["block_requested"])
    n_prot_block = sum(1 for r in prot_att if r["block_requested"])
    summary += [
        ["runs where legitimate host was flagged", "all 16 runs", len(table), n_flag, "", "", "runs"],
        ["block requested in normal-only runs (false blocks)", "8 normal-only runs", len(normal), n_false_block, "", "", "runs"],
        ["block requested in baseline attack runs", "baseline, normal+attack", len(base_att), n_base_block, "", "", "runs"],
        ["block requested in protected attack runs", "protected, normal+attack", len(prot_att), n_prot_block, "", "", "runs"],
    ]
    with open(os.path.join(args.out, "results_summary.csv"), "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["metric", "group", "n", "median", "min", "max", "unit"])
        w.writerows(summary)

    # Figure 1: detection time per attack run (log scale)
    fig, ax = plt.subplots(figsize=(7, 4.2))
    width = 0.38
    for i, (label, grp, color) in enumerate([("Baseline", base_att, "#8da0cb"), ("Protected", prot_att, "#fc8d62")]):
        xs = [r["trial"] + (i - 0.5) * width for r in grp]
        ys = [float(r["detection_ms"]) for r in grp]
        ax.bar(xs, ys, width, label=label, color=color)
        for x, y in zip(xs, ys):
            ax.text(x, y * 1.12, f"{y:.2f}", ha="center", fontsize=8)
    ax.set_yscale("log")
    ax.set_xticks(TRIALS)
    ax.set_xlabel("trial")
    ax.set_ylabel("detection time (ms, log scale)")
    ax.set_title("Detection time per attack run\n(first connection in window to alert)")
    ax.legend()
    fig.tight_layout()
    fig.savefig(os.path.join(args.out, "fig_detection_time.png"), dpi=150)
    plt.close(fig)

    # Figure 2: where the time goes, first attack connection -> DROP rule (protected runs)
    fig, ax = plt.subplots(figsize=(7, 4.2))
    trials = [r["trial"] for r in prot_att]
    det = [float(r["detection_ms"]) / 1000 for r in prot_att]
    req = [float(r["alert_to_request_ms"]) / 1000 for r in prot_att]
    drop = [float(r["request_to_drop_s"]) for r in prot_att]
    ax.bar(trials, det, label="detection (first conn to alert)", color="#66c2a5")
    ax.bar(trials, req, bottom=det, label="alert to block request", color="#ffd92f")
    ax.bar(trials, drop, bottom=[a + b for a, b in zip(det, req)],
           label="block request to DROP installed", color="#fc8d62")
    for t, r in zip(trials, prot_att):
        ax.text(t, float(r["first_attack_conn_to_drop_s"]) + 0.01,
                f"{float(r['first_attack_conn_to_drop_s']):.3f} s", ha="center", fontsize=9)
    ax.set_xticks(trials)
    ax.set_xlabel("trial")
    ax.set_ylabel("seconds")
    ax.set_title("Time from first attack connection to DROP rule (protected runs)")
    ax.legend(fontsize=8, loc="upper right")
    fig.tight_layout()
    fig.savefig(os.path.join(args.out, "fig_blocking_time.png"), dpi=150)
    plt.close(fig)

    print(f"{'metric':55}{'group':28}{'n':>3}{'median':>10}{'min':>10}{'max':>10}  unit")
    for s in summary:
        print(f"{s[0]:55}{s[1]:28}{s[2]:>3}{s[3]!s:>10}{s[4]!s:>10}{s[5]!s:>10}  {s[6]}")
    print("\nwrote results_per_run.csv, results_summary.csv, fig_detection_time.png, fig_blocking_time.png")


if __name__ == "__main__":
    main()
