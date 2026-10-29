import csv
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import requests
from filelock import FileLock

from sdn_defense import paths
from sdn_defense.detector import record_connection

PROJECT_DIR = paths.RUNTIME_DIR
EVENT_FILE = paths.CONNECTION_EVENTS_FILE
EVENT_LOCK = FileLock(str(paths.CONNECTION_EVENTS_LOCK_FILE))

BLOCK_EVENTS_FILE = paths.BLOCK_EVENTS_FILE
BLOCK_EVENTS_LOCK = FileLock(str(paths.BLOCK_EVENTS_LOCK_FILE))
CONTEXT_FILE = paths.CONTEXT_FILE

API_URL = "http://127.0.0.1:5000/block"
POLL_INTERVAL = 0.2

CSV_COLUMNS = [
    "run_id",
    "condition",
    "scenario",
    "trial",
    "source_ip",
    "event",
    "epoch_time",
]


def get_context():
    defaults = {
        "run_id": "unassigned",
        "condition": "unknown",
        "scenario": "unknown",
        "trial": 0,
    }

    try:
        context = json.loads(CONTEXT_FILE.read_text())
        if isinstance(context, dict):
            for key in defaults:
                if key in context:
                    defaults[key] = context[key]
    except (OSError, json.JSONDecodeError):
        pass

    return defaults


def log_block_event(source_ip, event):
    context = get_context()

    row = [
        context["run_id"],
        context["condition"],
        context["scenario"],
        context["trial"],
        source_ip,
        event,
        f"{time.time():.6f}",
    ]

    with BLOCK_EVENTS_LOCK:
        exists = (
            BLOCK_EVENTS_FILE.exists()
            and BLOCK_EVENTS_FILE.stat().st_size > 0
        )

        with BLOCK_EVENTS_FILE.open(
            "a", newline="", encoding="utf-8"
        ) as file:
            writer = csv.writer(file)

            if not exists:
                writer.writerow(CSV_COLUMNS)

            writer.writerow(row)


def read_events():
    with EVENT_LOCK:
        try:
            events = json.loads(EVENT_FILE.read_text())
        except (json.JSONDecodeError, OSError):
            return []

        if not isinstance(events, list):
            print("[ERROR] Event file must contain a JSON list")
            return []

        EVENT_FILE.write_text("[]")
        return events


def request_block(source_ip):
    print(f"[ACTION] Requesting block for {source_ip}")

    try:
        response = requests.post(
            API_URL,
            json={"ip": source_ip},
            timeout=3,
        )
        response.raise_for_status()

        log_block_event(source_ip, "block_requested")
        print(f"[ACTION] Block API response: {response.text}")
        return True

    except requests.RequestException as exc:
        print(f"[ERROR] Block request failed for {source_ip}: {exc}")
        return False


def main():
    requested_sources = set()

    print(f"Monitoring connection events from {EVENT_FILE}")
    print("Detector: detector.py")
    print(f"Threshold: configured in {paths.DETECTION_CONFIG}")

    context = get_context()
    print(f"Experiment context: {context}")

    if context["condition"] not in ("baseline", "protected"):
        print(
            "[ERROR] condition must be 'baseline' or 'protected'. "
            "Set experiment_context.json before starting the monitor."
        )
        return

    while True:
        try:
            events = read_events()

            for event in events:
                try:
                    source_ip = event["source_ip"]
                    destination_port = event["destination_port"]
                except (KeyError, TypeError):
                    print(f"[WARNING] Ignoring malformed event: {event!r}")
                    continue

                print(
                    f"Connection observed: {source_ip} "
                    f"-> port {destination_port}"
                )

                suspicious = record_connection(
                    source_ip,
                    destination_port,
                )

                # Baseline: detect and log, but never automatically block.
                # Protected: request one block per source per monitor session.
                if (
                    suspicious
                    and context["condition"] == "protected"
                    and source_ip not in requested_sources
                ):
                    if request_block(source_ip):
                        requested_sources.add(source_ip)

            time.sleep(POLL_INTERVAL)

        except KeyboardInterrupt:
            print("\nMonitor stopped.")
            break

        except Exception as exc:
            print(f"[ERROR] Monitor iteration failed: {exc}")
            time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    main()
