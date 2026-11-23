"""A stand-in for a residential proxy provider, for the smoke test.

Speaks the two things a provider offers and the firewall chains to: HTTP CONNECT with Basic auth
(port 8000) and SOCKS5 with username/password auth (port 1080). It records every tunnel it opens
as JSONL — `{proto, user, target}` — which is how the smoke asserts that the firewall CONNECTed by
NAME and which sticky session it presented. It never sees inside the tunnel, exactly like the real
thing.

CI needs no provider account, and nothing here should ever be pointed at real traffic: it prints
the username it was given.
"""

import base64
import json
import os
import select
import socket
import socketserver
import threading

HTTP_PORT = int(os.environ.get("UPSTREAM_HTTP_PORT", "8000"))
SOCKS_PORT = int(os.environ.get("UPSTREAM_SOCKS_PORT", "1080"))
USER = os.environ.get("UPSTREAM_USER", "acme")
PASSWORD = os.environ.get("UPSTREAM_PASSWORD", "pw")
LOG = os.environ.get("UPSTREAM_LOG", "/logs/upstream.jsonl")
_lock = threading.Lock()


def record(entry: dict) -> None:
    with _lock:
        with open(LOG, "a") as fh:
            fh.write(json.dumps(entry) + "\n")


def creds_ok(user: str, password: str) -> bool:
    """The username carries the session (`acme-sessid-ab12`), so match on the prefix like a
    provider does, and return the whole thing so the test can assert which session it was."""
    return password == PASSWORD and (user == USER or user.startswith(USER + "-"))


def relay(a: socket.socket, b: socket.socket) -> None:
    socks = [a, b]
    try:
        while True:
            ready, _, _ = select.select(socks, [], [], 60)
            if not ready:
                return
            for s in ready:
                data = s.recv(65536)
                if not data:
                    return
                (b if s is a else a).sendall(data)
    except OSError:
        return
    finally:
        for s in socks:
            try:
                s.close()
            except OSError:
                pass


def dial(host: str, port: int) -> socket.socket | None:
    try:
        return socket.create_connection((host, port), timeout=10)
    except OSError:
        return None


class ConnectHandler(socketserver.StreamRequestHandler):
    def handle(self):
        head = b""
        while b"\r\n\r\n" not in head and len(head) < 8192:
            chunk = self.connection.recv(4096)
            if not chunk:
                return
            head += chunk
        lines = head.split(b"\r\n")
        parts = lines[0].split()
        if len(parts) < 2 or parts[0].upper() != b"CONNECT":
            self.connection.sendall(b"HTTP/1.1 405 Method Not Allowed\r\n\r\n")
            return
        target = parts[1].decode()
        user = password = ""
        for line in lines[1:]:
            if line.lower().startswith(b"proxy-authorization: basic "):
                try:
                    user, password = base64.b64decode(line.split()[-1]).decode().split(":", 1)
                except Exception:
                    user = password = ""
        if not creds_ok(user, password):
            record({"proto": "http", "user": user, "target": target, "refused": "auth"})
            self.connection.sendall(b"HTTP/1.1 407 Proxy Authentication Required\r\n"
                                    b"Proxy-Authenticate: Basic realm=\"upstream\"\r\n\r\n")
            return
        host, _, port = target.rpartition(":")
        upstream = dial(host, int(port))
        if not upstream:
            record({"proto": "http", "user": user, "target": target, "refused": "connect"})
            self.connection.sendall(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
            return
        record({"proto": "http", "user": user, "target": target})
        self.connection.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
        relay(self.connection, upstream)


class SocksHandler(socketserver.StreamRequestHandler):
    def handle(self):
        conn = self.connection
        greeting = conn.recv(8)
        if len(greeting) < 3 or greeting[0] != 0x05 or 0x02 not in greeting[2:]:
            conn.sendall(b"\x05\xff")
            return
        conn.sendall(b"\x05\x02")
        head = conn.recv(2)
        if len(head) < 2 or head[0] != 0x01:
            return
        user = conn.recv(head[1]).decode()
        plen = conn.recv(1)
        password = conn.recv(plen[0]).decode() if plen else ""
        if not creds_ok(user, password):
            record({"proto": "socks5", "user": user, "target": "", "refused": "auth"})
            conn.sendall(b"\x01\x01")
            return
        conn.sendall(b"\x01\x00")
        req = conn.recv(4)
        if len(req) < 4 or req[1] != 0x01:
            conn.sendall(b"\x05\x07\x00\x01" + b"\x00" * 6)
            return
        atyp = req[3]
        if atyp == 0x03:
            host = conn.recv(conn.recv(1)[0]).decode()
        elif atyp == 0x01:
            host = socket.inet_ntoa(conn.recv(4))
        else:
            conn.sendall(b"\x05\x08\x00\x01" + b"\x00" * 6)
            return
        port = int.from_bytes(conn.recv(2), "big")
        upstream = dial(host, port)
        if not upstream:
            record({"proto": "socks5", "user": user, "target": f"{host}:{port}", "refused": "connect"})
            conn.sendall(b"\x05\x05\x00\x01" + b"\x00" * 6)
            return
        record({"proto": "socks5", "user": user, "target": f"{host}:{port}"})
        conn.sendall(b"\x05\x00\x00\x01" + b"\x00" * 6)
        relay(conn, upstream)


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def main():
    open(LOG, "a").close()
    http = Server(("0.0.0.0", HTTP_PORT), ConnectHandler)
    socks = Server(("0.0.0.0", SOCKS_PORT), SocksHandler)
    threading.Thread(target=socks.serve_forever, daemon=True).start()
    print(f"upstream proxy: CONNECT on :{HTTP_PORT}, SOCKS5 on :{SOCKS_PORT}", flush=True)
    http.serve_forever()


if __name__ == "__main__":
    main()
