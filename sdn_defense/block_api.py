import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from flask import Flask, request, jsonify, render_template
from filelock import FileLock
from datetime import datetime
import ipaddress
import json
import csv
import re
import subprocess

from sdn_defense import paths

app = Flask(__name__)

PROJECT_DIR = paths.RUNTIME_DIR
REQUEST_FILE = paths.REQUEST_FILE
REQUEST_LOCK = FileLock(str(paths.REQUEST_LOCK_FILE))
DETECTION_LOG = paths.DETECTION_LOG


def read_detection_log():
    """Read detection events from the CSV log."""
    events = []

    if not DETECTION_LOG.exists():
        return events

    try:
        with DETECTION_LOG.open(
            "r", newline="", encoding="utf-8"
        ) as file:
            reader = csv.DictReader(file)

            for row in reader:
                try:
                    epoch = float(row.get("epoch_time", 0))
                    row["epoch_time"] = epoch
                    row["time"] = datetime.fromtimestamp(
                        epoch
                    ).strftime("%Y-%m-%d %H:%M:%S")
                    row["source_ip"] = row.get("source_ip", "")
                    row["event"] = row.get("event", "")
                    row["count"] = row.get("count", "")
                    row["first_in_window"] = row.get(
                        "first_in_window", ""
                    )
                    events.append(row)
                except (ValueError, TypeError, OSError):
                    continue
    except OSError:
        app.logger.exception("Could not read detection log")

    return events


def queue_block_request(action, ip):
    """Queue a block/unblock request for the controller."""
    PROJECT_DIR.mkdir(parents=True, exist_ok=True)

    with REQUEST_LOCK:
        try:
            if REQUEST_FILE.exists():
                with REQUEST_FILE.open(
                    "r", encoding="utf-8"
                ) as file:
                    requests = json.load(file)
            else:
                requests = []

            if not isinstance(requests, list):
                requests = []

        except (json.JSONDecodeError, OSError):
            requests = []

        requests.append({
            "action": action,
            "ip": ip,
            "timestamp": datetime.now().isoformat(),
        })

        temporary_file = REQUEST_FILE.with_suffix(".tmp")

        with temporary_file.open("w", encoding="utf-8") as file:
            json.dump(requests, file, indent=2)

        temporary_file.replace(REQUEST_FILE)


@app.route("/")
def dashboard():
    return render_template("dashboard.html")


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "API is running"})


@app.route("/block", methods=["POST"])
def block_ip():
    data = request.get_json(silent=True) or {}
    ip = data.get("ip", "")

    try:
        ip = str(ipaddress.IPv4Address(ip))
    except (ipaddress.AddressValueError, ValueError, TypeError):
        return jsonify({"error": "A valid IPv4 address is required"}), 400

    queue_block_request("block", ip)

    return jsonify({
        "ip": ip,
        "message": "Block request queued",
    }), 202


@app.route("/unblock", methods=["POST"])
def unblock_ip():
    data = request.get_json(silent=True) or {}
    ip = data.get("ip", "")

    try:
        ip = str(ipaddress.IPv4Address(ip))
    except (ipaddress.AddressValueError, ValueError, TypeError):
        return jsonify({"error": "A valid IPv4 address is required"}), 400

    queue_block_request("unblock", ip)

    return jsonify({
        "ip": ip,
        "message": "Unblock request queued",
    }), 202


@app.route("/api/metrics", methods=["GET"])
def api_metrics():
    events = read_detection_log()

    connections = sum(
        1 for event in events if event.get("event") == "connection"
    )
    alerts = sum(
        1 for event in events if event.get("event") == "alert"
    )

    latest = max(
        (event["epoch_time"] for event in events),
        default=None,
    )

    last_updated = (
        datetime.fromtimestamp(latest).astimezone().isoformat()
        if latest is not None
        else None
    )

    return jsonify({
        "connections": connections,
        "alerts": alerts,
        "last_updated": last_updated,
    })


@app.route("/api/traffic", methods=["GET"])
def api_traffic():
    events = read_detection_log()

    # Exclude old synthetic/test timestamps from the dashboard.
    events = [
        event for event in events
        if event.get("epoch_time", 0) > 1_000_000_000
    ]

    events.sort(
        key=lambda event: event.get("epoch_time", 0),
        reverse=True,
    )

    return jsonify({"traffic": events[:30]})


@app.route("/api/status", methods=["GET"])
def api_status():
    """Report switch connectivity, controller connection, and active blocks."""
    try:
        switch_result = subprocess.run(
            [
                "sudo", "-n", "ovs-ofctl",
                "-O", "OpenFlow13", "dump-flows", "s1",
            ],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )

        if switch_result.returncode != 0:
            return jsonify({
                "controller": "unknown",
                "switch": "query failed",
                "blocked_ips": [],
                "blocked_count": 0,
                "error": switch_result.stderr.strip() or "Flow query failed",
            }), 503

        controller_result = subprocess.run(
            ["sudo", "-n", "ovs-vsctl", "show"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )

        if controller_result.returncode == 0:
            output = controller_result.stdout
            controller_online = bool(re.search(
                r'Controller "tcp:127\.0\.0\.1:6653"\s*\n\s*is_connected: true',
                output,
            ))
            controller_status = "online" if controller_online else "offline"
        else:
            controller_status = "unknown"

        blocked_ips = sorted(set(re.findall(
            r"priority=100,[^,\\n]*ip,nw_src=([0-9.]+)[^\\n]*actions=drop",
            switch_result.stdout,
        )))

        return jsonify({
            "controller": controller_status,
            "switch": "online",
            "blocked_ips": blocked_ips,
            "blocked_count": len(blocked_ips),
        })

    except (OSError, subprocess.TimeoutExpired) as exc:
        app.logger.warning("Status query failed: %s", exc)
        return jsonify({
            "controller": "unknown",
            "switch": "query failed",
            "blocked_ips": [],
            "blocked_count": 0,
            "error": str(exc),
        }), 503


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
