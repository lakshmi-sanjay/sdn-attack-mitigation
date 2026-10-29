import argparse
import socket
import sys
import threading
import time

lock = threading.Lock()
stats = {"attempted": 0, "connected": 0, "failed": 0, "blocked": 0}
stop_flag = threading.Event()


def one_connection(host, port, timeout, hold, messages):
    with lock:
        stats["attempted"] += 1
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((host, port))
        with lock:
            stats["connected"] += 1
        for i in range(messages):
            s.sendall(("PING\n").encode())
            s.recv(256)
        if hold > 0:
            end = time.time() + hold
            while time.time() < end and not stop_flag.is_set():
                time.sleep(0.05)
        try:
            s.sendall(b"QUIT\n")
        except OSError:
            pass
    except socket.timeout:
        with lock:
            stats["blocked"] += 1
    except OSError:
        with lock:
            stats["failed"] += 1
    finally:
        try:
            s.close()
        except OSError:
            pass


def generate(host, port, rate, duration, timeout, hold, messages, workers_cap):
    threads = []
    interval = 1.0 / rate
    start = time.time()
    nxt = start
    while time.time() - start < duration and not stop_flag.is_set():
        now = time.time()
        if now < nxt:
            time.sleep(min(nxt - now, 0.01))
            continue
        nxt += interval
        alive = [t for t in threads if t.is_alive()]
        threads = alive
        if len(threads) >= workers_cap:
            continue
        t = threading.Thread(target=one_connection, args=(host, port, timeout, hold, messages), daemon=True)
        t.start()
        threads.append(t)
    for t in threads:
        t.join(timeout + hold + 1)
    return time.time() - start


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=5000)
    p.add_argument("--mode", choices=["normal", "flood", "slow", "custom"], default="normal")
    p.add_argument("--rate", type=float, default=None)
    p.add_argument("--duration", type=float, default=None)
    p.add_argument("--timeout", type=float, default=2.0)
    p.add_argument("--hold", type=float, default=0.0)
    p.add_argument("--messages", type=int, default=0)
    p.add_argument("--max-parallel", type=int, default=1000)
    a = p.parse_args()

    presets = {
        "normal": (1.0, 10.0, 0.0, 1),
        "flood": (50.0, 10.0, 0.0, 0),
        "slow": (5.0, 20.0, 2.0, 0),
        "custom": (1.0, 10.0, 0.0, 0),
    }
    rate, duration, hold, msgs = presets[a.mode]
    if a.rate is not None:
        rate = a.rate
    if a.duration is not None:
        duration = a.duration
    if a.hold:
        hold = a.hold
    if a.messages:
        msgs = a.messages
    if rate <= 0 or duration <= 0:
        print("rate and duration must be positive", file=sys.stderr)
        sys.exit(1)

    print("mode=%s target=%s:%d rate=%.1f/s duration=%.1fs expected=%d" % (
        a.mode, a.host, a.port, rate, duration, int(rate * duration)))
    try:
        elapsed = generate(a.host, a.port, rate, duration, a.timeout, hold, msgs, a.max_parallel)
    except KeyboardInterrupt:
        stop_flag.set()
        elapsed = 0
    print("done elapsed=%.2fs attempted=%d connected=%d failed=%d blocked=%d" % (
        elapsed, stats["attempted"], stats["connected"], stats["failed"], stats["blocked"]))


if __name__ == "__main__":
    main()
