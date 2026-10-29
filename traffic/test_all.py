import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import client

PORT = 5055
PY = sys.executable
SERVER = str(HERE / "server.py")
CLIENT = str(HERE / "client.py")
TRAFFIC_GEN = str(HERE / "traffic_gen.py")
results = []


def check(name, cond):
    results.append((name, bool(cond)))
    print(("PASS  " if cond else "FAIL  ") + name, flush=True)


def start_server(extra=None):
    cmd = [PY, SERVER, "--host", "127.0.0.1", "--port", str(PORT)] + (extra or [])
    p = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for _ in range(50):
        try:
            socket.create_connection(("127.0.0.1", PORT), 0.2).close()
            return p
        except OSError:
            time.sleep(0.1)
    return p


def stop_server(p):
    p.terminate()
    try:
        p.wait(3)
    except subprocess.TimeoutExpired:
        p.kill()


def raw(data, wait=0.3, read=True):
    s = socket.create_connection(("127.0.0.1", PORT), 2)
    s.settimeout(2)
    s.sendall(data)
    time.sleep(wait)
    out = b""
    if read:
        try:
            out = s.recv(4096)
        except OSError:
            pass
    s.close()
    return out


def main():
    srv = start_server(["--idle-timeout", "2", "--max-clients", "30"])

    c = client.TCPClient("127.0.0.1", PORT, 2, 1)
    check("connection established", c.connect())
    check("HELLO", c.request("HELLO alice") == "OK HELLO alice")
    check("ECHO", c.request("ECHO hi there") == "ECHO hi there")
    check("PING", c.request("PING") == "PONG")
    check("TIME", c.request("TIME").startswith("TIME "))
    check("unknown command", c.request("FOO").startswith("ERR"))
    check("empty command", c.request("").startswith("ERR"))
    check("STATS", c.request("STATS").startswith("STATS "))
    check("QUIT", c.request("QUIT") == "BYE")
    c.close()

    c = client.TCPClient("127.0.0.1", PORT, 2, 1)
    c.connect()
    c.sock.sendall(b"PING\nPING\nPING\n")
    got = [c.recv_line() for _ in range(3)]
    check("pipelined messages", got == ["PONG"] * 3)
    c.close()

    check("fragmented message", raw(b"PI", 0.2, False) == b"" and True)
    s = socket.create_connection(("127.0.0.1", PORT), 2)
    s.sendall(b"PI")
    time.sleep(0.2)
    s.sendall(b"NG\n")
    s.settimeout(2)
    check("fragmented PING reassembled", s.recv(100) == b"PONG\n")
    s.close()

    check("invalid utf-8 handled", raw(b"\xff\xfe\n").startswith(b"ERR"))
    check("oversized line rejected", b"ERR line too long" in raw(b"A" * 9000))

    s = socket.create_connection(("127.0.0.1", PORT), 2)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, b"\x01\x00\x00\x00\x00\x00\x00\x00")
    s.sendall(b"ECHO abrupt\n")
    s.close()
    time.sleep(0.3)
    c = client.TCPClient("127.0.0.1", PORT, 2, 1)
    check("server survives abrupt disconnect", c.connect() and c.request("PING") == "PONG")
    c.close()

    s = socket.create_connection(("127.0.0.1", PORT), 2)
    s.settimeout(4)
    time.sleep(2.5)
    check("idle timeout", b"ERR idle timeout" in s.recv(100))
    s.close()

    ok = []

    def worker(i):
        cc = client.TCPClient("127.0.0.1", PORT, 3, 1)
        if cc.connect():
            good = cc.request("HELLO c%d" % i).startswith("OK")
            for j in range(5):
                good = good and cc.request("ECHO %d-%d" % (i, j)) == "ECHO %d-%d" % (i, j)
            cc.request("QUIT")
            ok.append(good)
        cc.close()

    ts = [threading.Thread(target=worker, args=(i,)) for i in range(25)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    check("25 concurrent clients", len(ok) == 25 and all(ok))

    holders = []
    for _ in range(30):
        h = socket.create_connection(("127.0.0.1", PORT), 2)
        holders.append(h)
    time.sleep(0.3)
    s = socket.create_connection(("127.0.0.1", PORT), 2)
    s.settimeout(2)
    check("max clients enforced", b"ERR server busy" in s.recv(100))
    s.close()
    [h.close() for h in holders]
    time.sleep(0.5)

    r = subprocess.run([PY, CLIENT, "--port", str(PORT), "--name", "bob", "--message", "x", "--pings", "2"],
                       capture_output=True, text=True, timeout=20)
    check("client CLI exit 0", r.returncode == 0 and "OK HELLO bob" in r.stdout and "ECHO x" in r.stdout)

    r = subprocess.run([PY, TRAFFIC_GEN, "--port", str(PORT), "--mode", "flood", "--rate", "40", "--duration", "5"],
                       capture_output=True, text=True, timeout=30)
    line = [l for l in r.stdout.splitlines() if l.startswith("done")][0]
    att = int(line.split("attempted=")[1].split()[0])
    con = int(line.split("connected=")[1].split()[0])
    check("flood: >=20 connections in 5s", att >= 190 and con >= 190)

    r = subprocess.run([PY, TRAFFIC_GEN, "--port", str(PORT), "--mode", "normal", "--rate", "2", "--duration", "5"],
                       capture_output=True, text=True, timeout=30)
    line = [l for l in r.stdout.splitlines() if l.startswith("done")][0]
    att = int(line.split("attempted=")[1].split()[0])
    check("normal: <20 connections in 5s", 8 <= att <= 12)

    r = subprocess.run([PY, TRAFFIC_GEN, "--port", str(PORT), "--mode", "slow", "--rate", "5", "--duration", "3", "--hold", "1"],
                       capture_output=True, text=True, timeout=30)
    check("slow/hold mode runs", "done" in r.stdout)

    stop_server(srv)
    time.sleep(0.3)

    r = subprocess.run([PY, CLIENT, "--port", str(PORT), "--retries", "2", "--retry-delay", "0.2"],
                       capture_output=True, text=True, timeout=20)
    check("server down: client fails gracefully (exit 2)", r.returncode == 2)

    r = subprocess.run([PY, TRAFFIC_GEN, "--port", str(PORT), "--rate", "10", "--duration", "1"],
                       capture_output=True, text=True, timeout=20)
    check("server down: generator reports failures", "failed=" in r.stdout and "connected=0" in r.stdout)

    r = subprocess.run([PY, TRAFFIC_GEN, "--rate", "0"], capture_output=True, text=True)
    check("invalid args rejected", r.returncode != 0)

    p1 = start_server()
    p2 = subprocess.run([PY, SERVER, "--host", "127.0.0.1", "--port", str(PORT)],
                        capture_output=True, text=True, timeout=10)
    check("port in use handled", p2.returncode == 1)
    stop_server(p1)

    failed = [n for n, ok in results if not ok]
    print("\n%d/%d passed" % (len(results) - len(failed), len(results)))
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
