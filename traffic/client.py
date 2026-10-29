import argparse
import socket
import sys
import time


class TCPClient:
    def __init__(self, host, port, timeout=5.0, retries=3, retry_delay=1.0):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.retries = retries
        self.retry_delay = retry_delay
        self.sock = None
        self.buf = b""

    def connect(self):
        last = None
        for attempt in range(1, self.retries + 1):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(self.timeout)
                s.connect((self.host, self.port))
                self.sock = s
                self.buf = b""
                return True
            except (ConnectionRefusedError, socket.timeout, OSError) as e:
                last = e
                try:
                    s.close()
                except OSError:
                    pass
                print("connect attempt %d/%d failed: %s" % (attempt, self.retries, e), file=sys.stderr)
                if attempt < self.retries:
                    time.sleep(self.retry_delay)
        print("could not connect to %s:%d (%s)" % (self.host, self.port, last), file=sys.stderr)
        return False

    def send_line(self, text):
        if self.sock is None:
            raise ConnectionError("not connected")
        self.sock.sendall((text + "\n").encode("utf-8"))

    def recv_line(self):
        if self.sock is None:
            raise ConnectionError("not connected")
        while b"\n" not in self.buf:
            chunk = self.sock.recv(1024)
            if not chunk:
                if self.buf:
                    line, self.buf = self.buf, b""
                    return line.decode("utf-8", "replace")
                raise ConnectionError("server closed connection")
            self.buf += chunk
        line, self.buf = self.buf.split(b"\n", 1)
        return line.decode("utf-8", "replace")

    def request(self, text):
        try:
            self.send_line(text)
            return self.recv_line()
        except socket.timeout:
            raise TimeoutError("no reply within %.1fs" % self.timeout)
        except (BrokenPipeError, ConnectionResetError) as e:
            raise ConnectionError(str(e))

    def close(self):
        if self.sock is not None:
            try:
                self.sock.close()
            except OSError:
                pass
            self.sock = None


def run(args):
    c = TCPClient(args.host, args.port, args.timeout, args.retries, args.retry_delay)
    if not c.connect():
        return 2
    try:
        if args.name:
            print(c.request("HELLO " + args.name))
        for m in args.message or []:
            print(c.request("ECHO " + m))
        for _ in range(args.pings):
            t0 = time.time()
            r = c.request("PING")
            print("%s (%.2f ms)" % (r, (time.time() - t0) * 1000))
            time.sleep(args.interval)
        if args.interactive:
            while True:
                try:
                    line = input("> ")
                except EOFError:
                    break
                if not line:
                    continue
                print(c.request(line))
                if line.strip().upper() == "QUIT":
                    break
        else:
            print(c.request("QUIT"))
        return 0
    except TimeoutError as e:
        print("timeout: %s" % e, file=sys.stderr)
        return 3
    except ConnectionError as e:
        print("connection error: %s" % e, file=sys.stderr)
        return 4
    finally:
        c.close()


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=5000)
    p.add_argument("--name", default="client")
    p.add_argument("--message", action="append")
    p.add_argument("--pings", type=int, default=0)
    p.add_argument("--interval", type=float, default=0.0)
    p.add_argument("--timeout", type=float, default=5.0)
    p.add_argument("--retries", type=int, default=3)
    p.add_argument("--retry-delay", type=float, default=1.0)
    p.add_argument("--interactive", action="store_true")
    sys.exit(run(p.parse_args()))


if __name__ == "__main__":
    main()
