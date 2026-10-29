import argparse
import json
import signal
import socket
import sys
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from filelock import FileLock

from sdn_defense import paths

MAX_LINE = 4096
state_lock = threading.Lock()
state = {"active": 0, "total": 0, "messages": 0, "rejected": 0}
running = threading.Event()
running.set()
EVENT_FILE = paths.CONNECTION_EVENTS_FILE
EVENT_LOCK = FileLock(str(paths.CONNECTION_EVENTS_LOCK_FILE))


def record_connection_event(source_ip, destination_port):
    event = {
        "source_ip": source_ip,
        "destination_port": destination_port,
        "timestamp": time.time(),
    }

    with EVENT_LOCK:
        try:
            events = json.loads(EVENT_FILE.read_text())
        except (json.JSONDecodeError, OSError):
            events = []

        events.append(event)
        EVENT_FILE.write_text(json.dumps(events))

def log(msg):
    print(time.strftime("%H:%M:%S"), msg, flush=True)


def handle_command(line, name):
    parts = line.strip().split(" ", 1)
    cmd = parts[0].upper()
    arg = parts[1] if len(parts) > 1 else ""
    if cmd == "HELLO":
        return "OK HELLO " + (arg or "anonymous"), (arg or "anonymous"), False
    if cmd == "ECHO":
        return "ECHO " + arg, name, False
    if cmd == "PING":
        return "PONG", name, False
    if cmd == "TIME":
        return "TIME " + time.strftime("%Y-%m-%d %H:%M:%S"), name, False
    if cmd == "STATS":
        with state_lock:
            s = dict(state)
        return "STATS active=%d total=%d messages=%d rejected=%d" % (
            s["active"], s["total"], s["messages"], s["rejected"]), name, False
    if cmd == "QUIT":
        return "BYE", name, True
    if cmd == "":
        return "ERR empty command", name, False
    return "ERR unknown command", name, False


def handle_client(conn, addr, idle_timeout):
    name = "anonymous"
    conn.settimeout(idle_timeout)
    buf = b""
    log("connected %s:%d" % addr)
    try:
        while running.is_set():
            try:
                chunk = conn.recv(1024)
            except socket.timeout:
                try:
                    conn.sendall(b"ERR idle timeout\n")
                except OSError:
                    pass
                break
            if not chunk:
                break
            buf += chunk
            if len(buf) > MAX_LINE and b"\n" not in buf:
                conn.sendall(b"ERR line too long\n")
                break
            done = False
            while b"\n" in buf:
                raw, buf = buf.split(b"\n", 1)
                if len(raw) > MAX_LINE:
                    conn.sendall(b"ERR line too long\n")
                    done = True
                    break
                try:
                    line = raw.decode("utf-8")
                except UnicodeDecodeError:
                    conn.sendall(b"ERR invalid encoding\n")
                    continue
                reply, name, quit_flag = handle_command(line, name)
                with state_lock:
                    state["messages"] += 1
                conn.sendall((reply + "\n").encode("utf-8"))
                if quit_flag:
                    done = True
                    break
            if done:
                break
    except (ConnectionResetError, BrokenPipeError, OSError) as e:
        log("client %s:%d error: %s" % (addr[0], addr[1], e))
    finally:
        try:
            conn.close()
        except OSError:
            pass
        with state_lock:
            state["active"] -= 1
        log("disconnected %s:%d" % addr)


def serve(host, port, max_clients, idle_timeout):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        srv.bind((host, port))
    except OSError as e:
        log("bind failed: %s" % e)
        return 1
    srv.listen(256)
    srv.settimeout(0.5)
    log("listening on %s:%d" % (host, port))

    def stop(signum, frame):
        running.clear()

    try:
        signal.signal(signal.SIGINT, stop)
        signal.signal(signal.SIGTERM, stop)
    except ValueError:
        pass

    while running.is_set():
        try:
            conn, addr = srv.accept()
        except socket.timeout:
            continue
        except OSError as e:
            if running.is_set():
                log("accept error: %s" % e)
            break

        record_connection_event(addr[0], port)

        with state_lock:
            if state["active"] >= max_clients:
                state["rejected"] += 1
                full = True
            else:
                state["active"] += 1
                state["total"] += 1
                full = False
        if full:
            try:
                conn.sendall(b"ERR server busy\n")
            except OSError:
                pass
            conn.close()
            continue
        t = threading.Thread(target=handle_client, args=(conn, addr, idle_timeout), daemon=True)
        t.start()
    srv.close()
    log("server stopped")
    return 0


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--host", default="0.0.0.0")
    p.add_argument("--port", type=int, default=5000)
    p.add_argument("--max-clients", type=int, default=500)
    p.add_argument("--idle-timeout", type=float, default=30.0)
    a = p.parse_args()
    sys.exit(serve(a.host, a.port, a.max_clients, a.idle_timeout))


if __name__ == "__main__":
    main()
