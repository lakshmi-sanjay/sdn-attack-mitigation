"""Unit tests for the detector (sdn_defense/detector.py).

Run from the repository root:
    python3 tests/test_monitor.py
Uses only the standard library. Replays traffic with the `now` argument, so it
finishes in about a second and never touches the real detection_log.csv.
"""
import contextlib
import csv
import io
import json
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
for p in (HERE, os.path.dirname(HERE)):
    if p not in sys.path:
        sys.path.insert(0, p)

from sdn_defense import detector as m

PY = sys.executable
TMP = tempfile.mkdtemp()
NO_CONFIG = os.path.join(TMP, "no_such_config.json")
results = []


def check(name, cond):
    results.append((name, bool(cond)))
    print(("PASS  " if cond else "FAIL  ") + name, flush=True)


def fresh():
    """Reset detector state and point config/log at harmless places."""
    m.reset()
    m.CONFIG_FILE = NO_CONFIG
    m.LOG_FILE = os.devnull


def feed(ip, times, threshold=5, window=5, base=1000.0):
    """Replay connections at the given offsets (seconds); return results, printed text."""
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        out = [m.record_connection(ip, 5000, threshold, window, now=base + t) for t in times]
    return out, buf.getvalue()


def main():
    fresh()
    out, _ = feed("10.0.0.1", [0, 1, 2, 3])
    check("4 connections in 5 s (threshold 5): not suspicious", out == [False] * 4)

    fresh()
    out, _ = feed("10.0.0.1", [0, 1, 2, 3, 4])
    check("5th connection within 5 s is suspicious", out == [False] * 4 + [True])

    fresh()
    out, _ = feed("10.0.0.1", [0, 1, 2, 3, 10])
    check("old connections leave the window (no alert)", out[-1] is False)

    fresh()
    out, _ = feed("10.0.0.1", [i * 2.0 for i in range(10)])
    check("slow host (1 per 2 s) never suspicious at 5/5s", not any(out))

    fresh()
    feed("10.0.0.2", [0, 0.1, 0.2, 0.3])
    out, _ = feed("10.0.0.3", [0.4])
    check("sources are tracked independently", out == [False])

    fresh()
    out, text = feed("10.0.0.2", [i * 0.1 for i in range(8)])
    check("keeps returning True after the threshold", out[4:] == [True] * 4)
    check("[ALERT] printed only once per source", text.count("[ALERT]") == 1)

    feed("10.0.0.2", [100], base=1000.0)
    check("flagged source stays remembered until cleared", "10.0.0.2" in m.suspicious_sources)
    m.clear_source("10.0.0.2")
    out, text = feed("10.0.0.2", [200 + i * 0.1 for i in range(5)])
    check("clear_source: source can be detected again", out[-1] is True and text.count("[ALERT]") == 1)

    m.reset()
    check("reset() clears all state", not m.suspicious_sources and not m.connection_history)

    fresh()
    path = os.path.join(TMP, "cfg.json")
    with open(path, "w") as f:
        json.dump({"threshold": 2, "window": 5}, f)
    m.CONFIG_FILE = path
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        out = [m.record_connection("10.0.0.4", 5000, now=1000.0 + i) for i in range(3)]
    check("config file threshold is used (2 -> alert on 2nd)", out == [False, True, True])

    fresh()
    with open(path, "w") as f:
        f.write("garbage")
    m.CONFIG_FILE = path
    check("invalid config falls back to defaults", m.load_config() == (5, 5.0))
    with open(path, "w") as f:
        json.dump({"threshold": 0, "window": 5}, f)
    check("out-of-range config falls back to defaults", m.load_config() == (5, 5.0))
    m.CONFIG_FILE = NO_CONFIG
    check("missing config falls back to defaults", m.load_config() == (5, 5.0))

    fresh()
    with open(path, "w") as f:
        json.dump({"threshold": 2, "window": 5}, f)
    m.CONFIG_FILE = path
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        out = [m.record_connection("10.0.0.5", 5000, threshold=4, now=1000.0 + i) for i in range(3)]
    check("explicit argument overrides config file", out == [False, False, False])

    fresh()
    log = os.path.join(TMP, "log.csv")
    m.LOG_FILE = log
    feed("10.0.0.6", [0, 0.1, 0.2, 0.3, 0.4])
    rows = list(csv.DictReader(open(log)))
    alerts = [r for r in rows if r["event"] == "alert"]
    check("log: 5 connection rows + 1 alert row", len(rows) == 6 and len(alerts) == 1)
    check("log: header columns are correct",
          list(rows[0].keys()) == ["event", "epoch_time", "source_ip", "count", "first_in_window"])
    if alerts:
        dt = float(alerts[0]["epoch_time"]) - float(alerts[0]["first_in_window"])
        check("log: detection time (alert - first_in_window) = 0.4 s", abs(dt - 0.4) < 1e-6)
    else:
        check("log: detection time computed", False)

    script = os.path.abspath(m.__file__)
    r = subprocess.run([PY, script, "--threshold", "0"], capture_output=True, text=True)
    check("CLI rejects --threshold 0", r.returncode != 0 and "threshold" in r.stderr)
    r = subprocess.run([PY, script, "--window", "-1"], capture_output=True, text=True)
    check("CLI rejects negative --window", r.returncode != 0)
    r = subprocess.run([PY, "-c", "import sdn_defense.detector"], capture_output=True, text=True,
                       cwd=os.path.dirname(HERE))
    check("importing the detector prints nothing", r.stdout == "" and r.returncode == 0)

    failed = [n for n, ok in results if not ok]
    print("\n%d/%d passed" % (len(results) - len(failed), len(results)))
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
