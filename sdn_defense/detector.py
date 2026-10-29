import argparse
import csv
import json
import os
import sys
import time
from collections import defaultdict, deque
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sdn_defense import paths

DEFAULT_THRESHOLD = 5
DEFAULT_WINDOW = 5.0
CONFIG_FILE = str(paths.DETECTION_CONFIG)
LOG_FILE = str(paths.DETECTION_LOG)

connection_history = defaultdict(deque)
suspicious_sources = set()


def load_config():
    """Read threshold/window from the config file; use defaults if unusable."""
    try:
        with open(CONFIG_FILE) as f:
            cfg = json.load(f)
        threshold = int(cfg["threshold"])
        window = float(cfg["window"])
        if threshold >= 1 and window > 0:
            return threshold, window
    except (OSError, ValueError, KeyError, TypeError):
        pass
    return DEFAULT_THRESHOLD, DEFAULT_WINDOW


def log_event(event, epoch, source_ip, count, first_in_window):
    """Append one row to the CSV used later for timing graphs."""
    is_new = not os.path.exists(LOG_FILE)
    with open(LOG_FILE, "a", newline="") as f:
        writer = csv.writer(f)
        if is_new:
            writer.writerow(
                ["event", "epoch_time", "source_ip", "count", "first_in_window"]
            )
        writer.writerow(
            [event, f"{epoch:.6f}", source_ip, count, f"{first_in_window:.6f}"]
        )


def record_connection(source_ip, destination_port=None,
                      threshold=None, window=None, now=None):
    """Record one connection attempt. Returns True if source is suspicious.

    threshold/window: if None, read from the config file.
    now: optional timestamp, so tests can replay traffic without sleeping.
    """
    if threshold is None or window is None:
        cfg_threshold, cfg_window = load_config()
        threshold = cfg_threshold if threshold is None else threshold
        window = cfg_window if window is None else window

    current_time = time.time() if now is None else now
    clock = datetime.fromtimestamp(current_time).strftime("%H:%M:%S")

    history = connection_history[source_ip]
    history.append(current_time)
    while history and current_time - history[0] > window:
        history.popleft()

    count = len(history)
    log_event("connection", current_time, source_ip, count, history[0])
    print(f"[TRAFFIC] {clock} | Source: {source_ip} | "
          f"Destination Port: {destination_port}")

    if count >= threshold:
        if source_ip not in suspicious_sources:
            suspicious_sources.add(source_ip)
            print(f"[ALERT] Intrusion detected from {source_ip} "
                  f"({count} connections in {window} seconds)")
            log_event("alert", current_time, source_ip, count, history[0])
            report_suspicious(source_ip)
        return True

    print(f"[NORMAL] {source_ip}: {count} connections in {window} seconds")
    return False


def report_suspicious(source_ip):
    print(f"[ACTION] Suspicious source identified: {source_ip}")


def clear_source(source_ip):
    """Forget a source, e.g. after its block expires or is removed."""
    suspicious_sources.discard(source_ip)
    connection_history.pop(source_ip, None)


def reset():
    """Clear all state, e.g. between experiment trials."""
    suspicious_sources.clear()
    connection_history.clear()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--threshold", type=int, default=None)
    parser.add_argument("--window", type=float, default=None)
    args = parser.parse_args()

    if (args.threshold is not None and args.threshold < 1) or (
        args.window is not None and args.window <= 0
    ):
        parser.error("threshold must be >= 1 and window must be > 0")

    print("Traffic Monitoring Module")
    print("\nSending 3 simulated events, 2 seconds apart...")
    for _ in range(3):
        record_connection("192.168.1.10", 5000, args.threshold, args.window)
        time.sleep(2)
    print("\nTest complete.")