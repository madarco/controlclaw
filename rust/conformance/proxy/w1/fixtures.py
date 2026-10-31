"""The servers a proxy case talks to through the proxy: origins, echoes, upstream proxies and the
firewall agent's loopback services. They run in the rig's own process, on an asyncio loop in a
thread, and record what reached them so a case can check it (and check that nothing did).

Every server listens on a fixed address on `lo` (rig.py adds them), so both proxies resolve the
same names through /etc/hosts and dial the same places.
"""
from __future__ import annotations

import asyncio
import base64
import json
import os
import socket
import ssl
import threading
from dataclasses import dataclass, field
from typing import Any

# Where things listen. 203.0.113.0/24 and 198.51.100.0/24 are documentation ranges: public as far
# as either proxy's address checks go, and routed nowhere but this rig's loopback.
ORIGIN_IP = "203.0.113.10"
ORIGIN2_IP = "203.0.113.11"
UPSTREAM_IP = "198.51.100.20"
PROXY_IP = "10.0.0.2"
AGENT_IP = "10.0.0.3"
AGENT2_IP = "10.0.0.4"
UNKNOWN_IP = "10.0.0.9"

GREETING = b"\x00server-first"


@dataclass
class Seen:
    """What one server saw. Reset before every case."""

    connections: int = 0
    received: bytearray = field(default_factory=bytearray)
    requests: list[dict[str, Any]] = field(default_factory=list)
    # Request lines an upstream proxy got (`CONNECT host:port HTTP/1.1`, or the SOCKS5 target).
    upstream: list[str] = field(default_factory=list)

    def reset(self) -> None:
        self.connections = 0
        self.received.clear()
        self.requests.clear()
        self.upstream.clear()


async def _read_head(reader: asyncio.StreamReader) -> bytes:
    return await reader.readuntil(b"\r\n\r\n")


async def _read_body(reader: asyncio.StreamReader, headers: dict[str, str]) -> bytes:
    if headers.get("transfer-encoding", "").lower() == "chunked":
        body = bytearray()
        while True:
            size = int((await reader.readline()).split(b";")[0].strip() or b"0", 16)
            if size == 0:
                await reader.readline()
                return bytes(body)
            body.extend(await reader.readexactly(size))
            await reader.readline()
    length = int(headers.get("content-length", "0") or 0)
    return await reader.readexactly(length) if length else b""


def _parse_head(head: bytes) -> tuple[str, str, dict[str, str], list[tuple[str, str]]]:
    lines = head.decode("latin-1").split("\r\n")
    method, target, _ = (lines[0].split(" ", 2) + ["", ""])[:3]
    raw = []
    for line in lines[1:]:
        if not line:
            continue
        k, _, v = line.partition(":")
        raw.append((k.strip(), v.strip()))
    return method, target, {k.lower(): v for k, v in raw}, raw


class Origin:
    """An HTTP/1.1 server that answers with JSON describing the request it got.

    A request may say how to be answered with `x-rig-respond: <base64 JSON>` holding `status`,
    `headers` and `body` (text) or `body_b64`: that is how cases get a 402 from a model gateway, a
    4xx with a body, a gzip body. The request is still recorded.
    """

    def __init__(self, seen: Seen, tls: ssl.SSLContext | None):
        self.seen = seen
        self.tls = tls

    async def handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        self.seen.connections += 1
        try:
            while True:
                try:
                    head = await _read_head(reader)
                except (asyncio.IncompleteReadError, ConnectionError):
                    return
                method, target, headers, raw = _parse_head(head)
                body = await _read_body(reader, headers)
                sni = None
                obj = writer.get_extra_info("ssl_object")
                if obj is not None:
                    sni = getattr(obj, "rig_sni", None)
                sink = headers.get("x-rig-sink") is not None
                req = {"method": method, "path": target, "headers": dict(raw),
                       "body": "" if sink else body.decode("utf-8", "replace"),
                       "sni": sni, "tls": obj is not None, "received": len(body)}
                self.seen.requests.append(req)
                # `/bytes/<n>`: n bytes, written a megabyte at a time (a big download).
                if target.startswith("/bytes/") and target[7:].isdigit():
                    n = int(target[7:])
                    writer.write(f"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {n}\r\n\r\n".encode())
                    chunk = b"\0" * (1 << 20)
                    while n > 0:
                        writer.write(chunk[:min(n, len(chunk))])
                        n -= min(n, len(chunk))
                        await writer.drain()
                    if headers.get("connection", "").lower() == "close":
                        return
                    continue
                status, extra, out = 200, {"Content-Type": "application/json"}, None
                spec = headers.get("x-rig-respond")
                if spec:
                    s = json.loads(base64.b64decode(spec))
                    status = int(s.get("status", 200))
                    extra = s.get("headers", {})
                    out = base64.b64decode(s["body_b64"]) if "body_b64" in s else s.get("body", "").encode()
                if out is None:
                    out = json.dumps(req).encode()
                reason = {200: "OK", 402: "Payment Required", 401: "Unauthorized", 403: "Forbidden",
                          429: "Too Many Requests", 404: "Not Found"}.get(status, "Status")
                lines = [f"HTTP/1.1 {status} {reason}"] + [f"{k}: {v}" for k, v in extra.items()]
                if not any(k.lower() == "content-length" for k in extra):
                    lines.append(f"Content-Length: {len(out)}")
                writer.write(("\r\n".join(lines) + "\r\n\r\n").encode("latin-1") + out)
                await writer.drain()
                if headers.get("connection", "").lower() == "close":
                    return
        except (ConnectionError, ssl.SSLError):
            pass
        finally:
            writer.close()


class Echo:
    """Raw TCP (or TLS) echo that speaks first: what test_tcp_drop.py's origin does."""

    def __init__(self, seen: Seen):
        self.seen = seen

    async def handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        self.seen.connections += 1
        try:
            writer.write(GREETING)
            await writer.drain()
            while chunk := await reader.read(65536):
                self.seen.received.extend(chunk)
                writer.write(chunk)
                await writer.drain()
        except (ConnectionError, ssl.SSLError):
            pass
        finally:
            writer.close()


class Upstream:
    """The organization's residential exit: an HTTP proxy (CONNECT, and absolute-form plain HTTP)
    on 3128 and a SOCKS5 proxy on 1080, both on UPSTREAM_IP. Each records what it was asked
    (`CONNECT host:port`, `GET http://...`, `SOCKS5 host:port`) and the credential it got
    (`user:password`). A case sets `password` to make it refuse a wrong one."""

    def __init__(self, seen: Seen):
        self.seen = seen
        self.user = "u"
        self.password = "p"
        self.auths: list[str] = []

    async def _relay(self, reader, writer, r2, w2) -> None:
        async def copy(src, dst):
            try:
                while chunk := await src.read(65536):
                    dst.write(chunk)
                    await dst.drain()
            except (ConnectionError, asyncio.IncompleteReadError):
                pass
            finally:
                try:
                    dst.write_eof()
                except (OSError, RuntimeError):
                    dst.close()
        await asyncio.gather(copy(reader, w2), copy(r2, writer))

    async def http(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            head = await _read_head(reader)
            method, target, headers, raw = _parse_head(head)
            auth = headers.get("proxy-authorization", "")
            cred = base64.b64decode(auth[6:]).decode() if auth.lower().startswith("basic ") else ""
            self.auths.append(cred)
            self.seen.upstream.append(f"{method} {target}")
            if cred != f"{self.user}:{self.password}":
                writer.write(b"HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 0\r\n\r\n")
                await writer.drain()
                return
            if method == "CONNECT":
                host, _, port = target.rpartition(":")
                r2, w2 = await asyncio.open_connection(host.strip("[]"), int(port))
                writer.write(b"HTTP/1.1 200 Connection established\r\n\r\n")
                await writer.drain()
                await self._relay(reader, writer, r2, w2)
                return
            # Absolute-form: send it on in origin form, answer with what comes back.
            rest = target.split("://", 1)[1]
            authority, _, path = rest.partition("/")
            host, _, port = authority.partition(":")
            body = await _read_body(reader, headers)
            r2, w2 = await asyncio.open_connection(host, int(port or 80))
            lines = [f"{method} /{path} HTTP/1.1"] + [f"{k}: {v}" for k, v in raw
                                                       if k.lower() not in ("proxy-authorization", "proxy-connection", "connection")]
            lines.append("Connection: close")
            w2.write(("\r\n".join(lines) + "\r\n\r\n").encode("latin-1") + body)
            await w2.drain()
            while chunk := await r2.read(65536):
                writer.write(chunk)
            await writer.drain()
        except (ConnectionError, asyncio.IncompleteReadError, OSError):
            pass
        finally:
            writer.close()

    async def socks(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            ver, n = await reader.readexactly(2)
            methods = await reader.readexactly(n)
            if 2 not in methods:
                writer.write(b"\x05\xff")
                return
            writer.write(b"\x05\x02")
            await writer.drain()
            _, ulen = await reader.readexactly(2)
            user = (await reader.readexactly(ulen)).decode()
            plen = (await reader.readexactly(1))[0]
            pw = (await reader.readexactly(plen)).decode()
            self.auths.append(f"{user}:{pw}")
            ok = user == self.user and pw == self.password
            writer.write(b"\x01\x00" if ok else b"\x01\x01")
            await writer.drain()
            if not ok:
                return
            _, cmd, _, atyp = await reader.readexactly(4)
            if atyp == 3:
                hlen = (await reader.readexactly(1))[0]
                host = (await reader.readexactly(hlen)).decode()
            else:
                host = socket.inet_ntoa(await reader.readexactly(4))
            port = int.from_bytes(await reader.readexactly(2), "big")
            self.seen.upstream.append(f"SOCKS5 {host}:{port}" + ("" if atyp == 3 else " (by address)"))
            r2, w2 = await asyncio.open_connection(host, port)
            writer.write(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
            await writer.drain()
            await self._relay(reader, writer, r2, w2)
        except (ConnectionError, asyncio.IncompleteReadError, OSError):
            pass
        finally:
            writer.close()


class WsEcho:
    """A websocket server that echoes each message back as `echo:<text>` (binary as it came), and
    closes when it gets `close-me`. Records each handshake's headers (`requests`) and every message
    it got (`received`, joined by newlines)."""

    def __init__(self, seen: Seen):
        self.seen = seen

    async def handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        import wsproto
        import wsproto.events as ev
        self.seen.connections += 1
        ws = wsproto.WSConnection(wsproto.ConnectionType.SERVER)
        try:
            while True:
                data = await reader.read(65536)
                if not data:
                    return
                ws.receive_data(data)
                for e in ws.events():
                    if isinstance(e, ev.Request):
                        self.seen.requests.append({"path": e.target, "headers": {k.decode(): v.decode() for k, v in e.extra_headers},
                                                   "extensions": [str(x) for x in e.extensions]})
                        writer.write(ws.send(ev.AcceptConnection()))
                    elif isinstance(e, ev.TextMessage):
                        self.seen.received.extend((e.data + "\n").encode())
                        if e.data == "close-me":
                            writer.write(ws.send(ev.CloseConnection(code=1000, reason="bye")))
                        else:
                            writer.write(ws.send(ev.Message(data="echo:" + e.data)))
                    elif isinstance(e, ev.BytesMessage):
                        self.seen.received.extend(bytes(e.data) + b"\n")
                        writer.write(ws.send(ev.Message(data=bytes(e.data))))
                    elif isinstance(e, ev.CloseConnection):
                        writer.write(ws.send(e.response()))
                        await writer.drain()
                        return
                    elif isinstance(e, ev.Ping):
                        writer.write(ws.send(e.response()))
                await writer.drain()
        except (ConnectionError, ssl.SSLError, Exception):  # noqa: BLE001
            pass
        finally:
            writer.close()


class Judge:
    """The firewall agent's AI judge on 127.0.0.1:3101 (`/judge`). The answer comes from
    `answer` (set by a case); every payload is recorded."""

    def __init__(self, seen: Seen):
        self.seen = seen
        self.answer: dict[str, Any] | None = {"decision": "fallback"}
        self.delay = 0.0

    async def handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            head = await _read_head(reader)
            method, target, headers, _ = _parse_head(head)
            body = await _read_body(reader, headers)
            self.seen.requests.append({"method": method, "path": target, "json": json.loads(body or b"null")})
            if self.delay:
                await asyncio.sleep(self.delay)
            out = json.dumps(self.answer).encode()
            writer.write(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: "
                         + str(len(out)).encode() + b"\r\nConnection: close\r\n\r\n" + out)
            await writer.drain()
        except (ConnectionError, asyncio.IncompleteReadError, json.JSONDecodeError):
            pass
        finally:
            writer.close()


class NoRecords(asyncio.DatagramProtocol):
    """The proxy namespace's DNS server: every question answered "no records" (NOERROR, empty). Names
    come from /etc/hosts; a name that is not there does not resolve, as on a box with no answer."""

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        if len(data) < 12:
            return
        # Same id, response bit, recursion available, NOERROR, the question echoed, no answers.
        flags = bytes([0x81, 0x80])
        # Only the question (name, type, class): an EDNS record after it is not answered.
        end = 12
        while end < len(data) and data[end] != 0:
            end += data[end] + 1
        end += 5
        out = data[:2] + flags + b"\x00\x01" + b"\x00\x00\x00\x00\x00\x00" + data[12:end]
        self.transport.sendto(out, addr)


def netns_socket(netns: str, host: str, port: int) -> socket.socket:
    """A listening socket in another network namespace: made on a thread that has joined it."""
    out: list[socket.socket] = []

    def make() -> None:
        with open(f"/run/netns/{netns}") as f:
            os.setns(f.fileno(), os.CLONE_NEWNET)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((host, port))
        s.listen(128)
        s.setblocking(False)
        out.append(s)

    t = threading.Thread(target=make)
    t.start()
    t.join()
    return out[0]


class Fixtures:
    """Starts every server once; `reset()` clears what they saw before each case."""

    def __init__(self, origin_tls: ssl.SSLContext):
        self.loop = asyncio.new_event_loop()
        self.origin = Seen()
        self.echo = Seen()
        self.judge_seen = Seen()
        self.judge = Judge(self.judge_seen)
        self.upstream_seen = Seen()
        self.ws_seen = Seen()
        self.ws = WsEcho(self.ws_seen)
        self.upstream = Upstream(self.upstream_seen)
        self.origin_tls = origin_tls
        self._servers: list[asyncio.base_events.Server] = []
        threading.Thread(target=self.loop.run_forever, daemon=True).start()
        self.call(self._start())

    def call(self, coro):
        return asyncio.run_coroutine_threadsafe(coro, self.loop).result(30)

    async def _start(self) -> None:
        origin = Origin(self.origin, None)
        origin_tls = Origin(self.origin, self.origin_tls)
        echo = Echo(self.echo)
        for host in (ORIGIN_IP, ORIGIN2_IP):
            self._servers += [
                await asyncio.start_server(self.ws.handle, host, 9443, ssl=self.origin_tls),
                await asyncio.start_server(self.ws.handle, host, 9080),
                await asyncio.start_server(origin.handle, host, 80),
                await asyncio.start_server(origin_tls.handle, host, 443, ssl=self.origin_tls),
                await asyncio.start_server(origin_tls.handle, host, 8443, ssl=self.origin_tls),
                await asyncio.start_server(echo.handle, host, 7000),
                await asyncio.start_server(echo.handle, host, 7443, ssl=self.origin_tls),
            ]
        await self.loop.create_datagram_endpoint(NoRecords, local_addr=("10.0.0.1", 53))
        self._servers += [
            await asyncio.start_server(self.upstream.http, UPSTREAM_IP, 3128),
            await asyncio.start_server(self.upstream.socks, UPSTREAM_IP, 1080),
        ]
        # The firewall agent's loopback services are on the proxy's own loopback, in its namespace.
        self._servers.append(await asyncio.start_server(self.judge.handle, sock=netns_socket("px", "127.0.0.1", 3101)))

    def reset(self) -> None:
        for s in (self.origin, self.echo, self.judge_seen, self.upstream_seen, self.ws_seen):
            s.reset()
        self.upstream.auths.clear()
        self.upstream.password = "p"
        self.judge.answer = {"decision": "fallback"}
        self.judge.delay = 0.0

    def seen(self, name: str) -> Seen:
        return {"origin": self.origin, "echo": self.echo, "judge": self.judge_seen,
                "upstream": self.upstream_seen, "ws": self.ws_seen}[name]
