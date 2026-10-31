#!/usr/bin/env python3
"""Wire-level proxy cases for W2 (the checks), against mitmproxy + addon.py or cc-proxy.

    rust/conformance/proxy/w2/run.py                      # every case, on mitmproxy
    rust/conformance/proxy/w2/run.py --target cc-proxy    # the same cases on the Rust proxy
    rust/conformance/proxy/w2/run.py --filter telegram rust/conformance/cases/w2/

A case (`rust/conformance/cases/w2/*.json`) is the config files the firewall agent would have
written, the answers of its loopback services, and steps: one HTTPS request from an agent through
the proxy (CONNECT, TLS with the name, the request), what the upstream answers if it is reached,
and what must come back, what the upstream saw, which loopback calls were made, and which lines
were added to `content-rules.jsonl` and `traffic.jsonl`.

The rig, all on this machine:
  - the proxy on 127.0.0.1 (the agent's source address is 127.0.0.1, named `vm_test` in
    identities.json);
  - one TLS upstream on this machine's own non-loopback address (the proxy refuses loopback
    targets), which answers every name: mitmproxy dials the CONNECT target and is told not to
    verify it (`ssl_insecure`); cc-proxy resolves the name through `MITM_DEV_RESOLVE` and
    `MITM_DEV_INSECURE_UPSTREAM`;
  - the loopback services as plain HTTP servers on ephemeral ports, reached through the
    `MITM_*_URL` variables the addon reads.

Stdlib only, apart from mitmproxy for that target: `MITM_PYTHON` (default `python3`) must be able
to `import mitmproxy` (12.2.2, as on the boxes).

Matchers in expected JSON: "$any", "$string", "$number", "$absent" (the key must not be there).
Expansions anywhere in a case: "$now+600" (epoch seconds from now, a number) and
{"$repeat": "x", "n": 70000} (a long string). A step's `files` are expanded when that step runs.
"""
from __future__ import annotations

import argparse
import base64
import http.client
import http.server
import json
import os
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
RUST = HERE.parent.parent.parent
REPO = RUST.parent
# The production addon to compare with: main's (`git show origin/main:packages/mitm-proxy/addon.py`)
# when this branch's copy is behind it.
ADDON = Path(os.environ.get("W2_ADDON") or REPO / "packages" / "mitm-proxy" / "addon.py")
CACHE = Path(os.environ.get("CC_RIG_CACHE", Path(tempfile.gettempdir()) / "cc-w2-rig"))

SERVICES = {
    # name: (environment variable, the path the variable carries)
    "judge": ("MITM_AI_JUDGE_URL", "/judge"),
    "content": ("MITM_CONTENT_RULES_URL", ""),
    "buttons": ("MITM_CODE_BUTTONS_URL", "/"),
    "email": ("MITM_EMAIL_ADMISSION_URL", "/"),
    "mcp": ("MITM_MCP_ADMISSION_URL", ""),
    # Fixed in the addon (no variable): the rig binds 127.0.0.1:8791 itself.
    "phone": (None, "/"),
}
FIXED_PORTS = {"phone": 8791}


# ---------------------------------------------------------------------------------------------
# matching


class Mismatch(Exception):
    def __str__(self):
        text = super().__str__()
        return text if len(text) < 1500 else text[:1500] + " ..."


def match(exp, got, where="", exact=True):
    if exp == "$any":
        return
    if exp == "$string":
        if not isinstance(got, str):
            raise Mismatch(f"{where}: want a string, got {got!r}")
        return
    if exp == "$number":
        if not isinstance(got, (int, float)) or isinstance(got, bool):
            raise Mismatch(f"{where}: want a number, got {got!r}")
        return
    if isinstance(exp, dict):
        if not isinstance(got, dict):
            raise Mismatch(f"{where}: want an object, got {got!r}")
        for k, v in exp.items():
            if v == "$absent":
                if k in got:
                    raise Mismatch(f"{where}.{k}: want it absent, got {got[k]!r}")
                continue
            if k not in got:
                raise Mismatch(f"{where}.{k}: missing in {got!r}")
            match(v, got[k], f"{where}.{k}", exact)
        if exact:
            extra = [k for k in got if k not in exp]
            if extra:
                raise Mismatch(f"{where}: unexpected keys {extra} in {got!r}")
        return
    if isinstance(exp, list):
        if not isinstance(got, list) or len(got) != len(exp):
            raise Mismatch(f"{where}: want {len(exp)} items, got {got!r}")
        for i, (e, g) in enumerate(zip(exp, got)):
            match(e, g, f"{where}[{i}]", exact)
        return
    if exp != got or type(exp) is not type(got) and not (isinstance(exp, (int, float)) and isinstance(got, (int, float))):
        raise Mismatch(f"{where}: want {exp!r}, got {got!r}")


def expand(v):
    if isinstance(v, str) and v.startswith("$now"):
        return time.time() + float(v[4:] or 0)
    if isinstance(v, dict):
        if "$repeat" in v:
            return v["$repeat"] * v["n"]
        return {k: expand(x) for k, x in v.items()}
    if isinstance(v, list):
        return [expand(x) for x in v]
    return v


# ---------------------------------------------------------------------------------------------
# fakes


class Recorder:
    """Answers by path from a queue (the last answer repeats until a new one is queued) and records calls."""

    def __init__(self):
        self.lock = threading.Lock()
        self.answers: dict[str, list] = {}
        self.used: dict[str, bool] = {}
        self.calls: list[dict] = []

    def queue(self, path, answers):
        with self.lock:
            q = self.answers.setdefault(path, [])
            if len(q) == 1 and self.used.get(path):
                q.clear()
            q.extend(answers)
            self.used[path] = False

    def take(self, path, default):
        with self.lock:
            q = self.answers.get(path) or self.answers.get("*")
            if not q:
                return default
            key = path if path in self.answers else "*"
            if len(q) > 1:
                return q.pop(0)
            self.used[key] = True
            return q[0]


def make_handler(rec: Recorder, kind: str):
    class Handler(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *a):
            pass

        def _ws(self):
            entry = {"method": self.command, "path": self.path, "headers": {k.lower(): v for k, v in self.headers.items()}, "body": "", "ws": []}
            with rec.lock:
                rec.calls.append(entry)
            script = rec.take("*ws", {})
            self.send_response(101)
            self.send_header("Upgrade", "websocket")
            self.send_header("Connection", "Upgrade")
            self.send_header("Sec-WebSocket-Accept", ws_accept(self.headers.get("sec-websocket-key", "")))
            for k, v in (script.get("headers") or {}).items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.flush()
            sock = self.connection

            def reader():
                entry["ws"].extend(ws_collect(sock, 1.5, 6))
            t = threading.Thread(target=reader, daemon=True)
            t.start()
            time.sleep(script.get("delay", 0.3))
            for frame in script.get("frames", []):
                ws_send(sock, frame if isinstance(frame, str) else json.dumps(frame), mask=False)
                time.sleep(0.05)
            t.join()
            self.close_connection = True

        def _all(self):
            if kind == "upstream" and self.headers.get("upgrade", "").lower() == "websocket":
                return self._ws()
            length = int(self.headers.get("content-length") or 0)
            body = self.rfile.read(length) if length else b""
            path = self.path
            entry = {"method": self.command, "path": path, "headers": {k.lower(): v for k, v in self.headers.items()},
                     "body": body.decode("utf-8", "replace")}
            try:
                entry["json"] = json.loads(body) if body else None
            except ValueError:
                pass
            with rec.lock:
                rec.calls.append(entry)
            lookup = path.split("?", 1)[0] if kind == "loopback" else path
            answer = rec.take(lookup, {"status": 200, "json": {}} if kind == "loopback" else {"status": 200, "json": {"ok": True}})
            if answer.get("delay"):
                time.sleep(answer["delay"])
            if answer.get("close"):
                self.close_connection = True
                return
            status = answer.get("status", 200)
            headers = dict(answer.get("headers") or {})
            if "json" in answer:
                payload = json.dumps(answer["json"]).encode()
                headers.setdefault("Content-Type", "application/json")
            elif "body_b64" in answer:
                payload = base64.b64decode(answer["body_b64"])
            else:
                payload = str(answer.get("body", "")).encode()
            try:
                self.send_response(status)
                for k, v in headers.items():
                    self.send_header(k, v)
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)
            except (BrokenPipeError, ConnectionResetError):
                pass  # the proxy gave up waiting (a slow fake)

        do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = do_HEAD = _all

    return Handler


def serve(handler, host="127.0.0.1", tls: ssl.SSLContext | None = None, port: int = 0):
    try:
        srv = http.server.ThreadingHTTPServer((host, port), handler)
    except OSError:
        srv = http.server.ThreadingHTTPServer((host, 0), handler)
    srv.daemon_threads = True
    if tls is not None:
        srv.socket = tls.wrap_socket(srv.socket, server_side=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def own_address() -> str:
    if os.environ.get("CC_RIG_UPSTREAM_IP"):
        return os.environ["CC_RIG_UPSTREAM_IP"]
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.connect(("10.255.255.255", 1))
        return s.getsockname()[0]


def upstream_cert() -> tuple[Path, Path]:
    CACHE.mkdir(parents=True, exist_ok=True)
    cert, key = CACHE / "upstream.pem", CACHE / "upstream-key.pem"
    if not cert.exists():
        subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
                        "-days", "3650", "-subj", "/CN=upstream.test", "-keyout", str(key), "-out", str(cert)],
                       check=True, capture_output=True)
    return cert, key


# ---------------------------------------------------------------------------------------------
# websockets (RFC 6455, text frames only, no extensions)


def ws_accept(key: str) -> str:
    import hashlib
    return base64.b64encode(hashlib.sha1((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest()).decode()


def ws_send(sock, text: str, mask: bool) -> None:
    data = text.encode()
    head = bytearray([0x81])
    n = len(data)
    m = 0x80 if mask else 0
    if n < 126:
        head.append(m | n)
    elif n < 65536:
        head += bytes([m | 126]) + n.to_bytes(2, "big")
    else:
        head += bytes([m | 127]) + n.to_bytes(8, "big")
    if mask:
        key = os.urandom(4)
        head += key
        data = bytes(b ^ key[i % 4] for i, b in enumerate(data))
    sock.sendall(bytes(head) + data)


def ws_recv(sock, buf: bytearray):
    """One frame (opcode, payload), or None when the connection ends."""
    def need(n):
        while len(buf) < n:
            chunk = sock.recv(65536)
            if not chunk:
                return False
            buf.extend(chunk)
        return True
    if not need(2):
        return None
    op, n, masked = buf[0] & 0x0F, buf[1] & 0x7F, buf[1] & 0x80
    at = 2
    if n == 126:
        if not need(4):
            return None
        n, at = int.from_bytes(buf[2:4], "big"), 4
    elif n == 127:
        if not need(10):
            return None
        n, at = int.from_bytes(buf[2:10], "big"), 10
    key = b""
    if masked:
        if not need(at + 4):
            return None
        key, at = bytes(buf[at:at + 4]), at + 4
    if not need(at + n):
        return None
    payload = bytes(buf[at:at + n])
    del buf[:at + n]
    if masked:
        payload = bytes(b ^ key[i % 4] for i, b in enumerate(payload))
    return op, payload


def ws_collect(sock, quiet: float, limit: float) -> list:
    """Text frames until nothing came for `quiet` seconds (or `limit` in all)."""
    out, buf, end = [], bytearray(), time.time() + limit
    while time.time() < end:
        sock.settimeout(quiet)
        try:
            frame = ws_recv(sock, buf)
        except (socket.timeout, TimeoutError):
            break
        except OSError:
            break
        if frame is None or frame[0] == 8:
            break
        if frame[0] == 1:
            out.append(frame[1].decode("utf-8", "replace"))
    return out


def ws_doc(text: str):
    try:
        return json.loads(text)
    except ValueError:
        return text


# ---------------------------------------------------------------------------------------------
# the proxy


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def addon_script() -> Path:
    """The addon mitmdump loads. Main's addon (since #511) refuses to dial the firewall's own
    address, and the rig's upstream listens on this machine's: under `W2_ADDON` it is loaded through a
    shim that turns only that guard off."""
    if not os.environ.get("W2_ADDON"):
        return ADDON
    shim = CACHE / "w2_addon_shim.py"
    shim.write_text(
        "import importlib.util, sys\n"
        f"spec = importlib.util.spec_from_file_location('cc_addon', {str(ADDON)!r})\n"
        "cc_addon = importlib.util.module_from_spec(spec)\n"
        "sys.modules['cc_addon'] = cc_addon\n"
        "spec.loader.exec_module(cc_addon)\n"
        "cc_addon.is_own_address = lambda ip: False  # the rig's upstream is on this machine\n"
        "from cc_addon import *  # noqa: F401,F403 (mitmproxy finds the hooks here)\n"
    )
    return shim


class Proxy:
    def __init__(self, target: str, env: dict, hosts: list[str], upstream: tuple[str, int], logdir: Path):
        self.port = free_port()
        cadir = CACHE / "ca"
        cadir.mkdir(parents=True, exist_ok=True)
        self.ca_cert = cadir / "mitmproxy-ca-cert.pem"
        env = {**env}
        if target == "mitmproxy":
            mitm_python = os.environ.get("MITM_PYTHON", "python3")
            cmd = [mitm_python, "-c", "from mitmproxy.tools.main import mitmdump; mitmdump()",
                   "--listen-host", "127.0.0.1", "--listen-port", str(self.port), "--set", "flow_detail=0",
                   "--set", "connection_strategy=lazy", "--set", f"confdir={cadir}", "--set", "ssl_insecure=true",
                   "-s", str(addon_script())]
        else:
            binary = os.environ.get("CC_PROXY_BIN", str(RUST / "target" / "debug" / "cc-proxy"))
            cmd = [binary, "--listen", f"127.0.0.1:{self.port}"]
            env.update({"MITM_CA_DIR": str(cadir), "MITM_ALLOW_DEV_FLAGS": "1", "MITM_DEV_INSECURE_UPSTREAM": "1",
                        "MITM_DEV_RESOLVE": ",".join(f"{h}={upstream[0]}:{upstream[1]}" for h in hosts)})
        self.log = open(logdir / f"{target}.log", "w")
        self.proc = subprocess.Popen(cmd, env=env, stdout=self.log, stderr=subprocess.STDOUT, cwd=str(ADDON.parent))
        deadline = time.time() + 30
        while time.time() < deadline:
            if self.proc.poll() is not None:
                raise RuntimeError(f"the proxy exited: {(logdir / f'{target}.log').read_text()[-2000:]}")
            try:
                socket.create_connection(("127.0.0.1", self.port), timeout=0.2).close()
                if self.ca_cert.exists():
                    return
            except OSError:
                pass
            time.sleep(0.1)
        raise RuntimeError("the proxy did not start")

    def stop(self):
        self.proc.terminate()
        try:
            self.proc.wait(5)
        except subprocess.TimeoutExpired:
            self.proc.kill()
        self.log.close()


def ws_through_proxy(proxy: Proxy, upstream: tuple[str, int], ws: dict, timeout: float) -> tuple[int, list]:
    """Open a websocket through the proxy, send the client frames, collect what the server sends."""
    host = ws["host"]
    sock = socket.create_connection(("127.0.0.1", proxy.port), timeout=timeout)
    sock.sendall(f"CONNECT {upstream[0]}:{upstream[1]} HTTP/1.1\r\nHost: {upstream[0]}:{upstream[1]}\r\n\r\n".encode())
    head = b""
    while b"\r\n\r\n" not in head:
        head += sock.recv(4096)
    ctx = ssl.create_default_context(cafile=str(proxy.ca_cert))
    tls = ctx.wrap_socket(sock, server_hostname=host)
    key = base64.b64encode(os.urandom(16)).decode()
    extra = "".join(f"{k}: {v}\r\n" for k, v in (ws.get("headers") or {}).items())
    tls.sendall((f"GET {ws['path']} HTTP/1.1\r\nHost: {host}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                 f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n{extra}\r\n").encode())
    resp = b""
    while b"\r\n\r\n" not in resp:
        chunk = tls.recv(4096)
        if not chunk:
            break
        resp += chunk
    status = int(resp.split(b" ", 2)[1]) if resp.startswith(b"HTTP/") else 0
    if status != 101:
        tls.close()
        return status, []
    for frame in ws.get("frames", []):
        ws_send(tls, frame if isinstance(frame, str) else json.dumps(frame), mask=True)
        time.sleep(0.05)
    got = ws_collect(tls, 1.5, 8)
    tls.close()
    return status, got


def through_proxy(proxy: Proxy, upstream: tuple[str, int], req: dict, timeout: float) -> tuple[int, dict, bytes]:
    host = req["host"]
    sock = socket.create_connection(("127.0.0.1", proxy.port), timeout=timeout)
    sock.sendall(f"CONNECT {upstream[0]}:{upstream[1]} HTTP/1.1\r\nHost: {upstream[0]}:{upstream[1]}\r\n\r\n".encode())
    head = b""
    while b"\r\n\r\n" not in head:
        chunk = sock.recv(4096)
        if not chunk:
            raise ConnectionError("the proxy closed the CONNECT")
        head += chunk
    if b" 200 " not in head.split(b"\r\n", 1)[0]:
        raise ConnectionError(f"CONNECT refused: {head[:80]!r}")
    ctx = ssl.create_default_context(cafile=str(proxy.ca_cert))
    tls = ctx.wrap_socket(sock, server_hostname=host)
    conn = http.client.HTTPConnection(host, timeout=timeout)
    conn.sock = tls
    headers = dict(req.get("headers") or {})
    body = None
    if "json" in req:
        body = json.dumps(req["json"]).encode()
        headers.setdefault("Content-Type", "application/json")
    elif "form" in req:
        from urllib.parse import urlencode
        body = urlencode(req["form"]).encode()
        headers.setdefault("Content-Type", "application/x-www-form-urlencoded")
    elif "body_b64" in req:
        body = base64.b64decode(req["body_b64"])
    elif "body" in req:
        body = req["body"].encode()
    conn.request(req.get("method", "GET"), req["path"], body=body, headers=headers)
    res = conn.getresponse()
    data = res.read()
    out = (res.status, {k.lower(): v for k, v in res.getheaders()}, data)
    conn.close()
    return out


# ---------------------------------------------------------------------------------------------
# a case


def bump(path: Path, text: str):
    path.write_text(text)
    st = os.stat(path)
    os.utime(path, ns=(st.st_atime_ns, st.st_mtime_ns + 1_000_000))


def lines(path: Path) -> list[dict]:
    if not path.exists():
        return []
    return [json.loads(l) for l in path.read_text().splitlines() if l.strip()]


def run_case(case: dict, target: str, keep: bool) -> None:
    tmp = Path(tempfile.mkdtemp(prefix="w2-case-"))
    config, logs = tmp / "config", tmp / "logs"
    config.mkdir()
    logs.mkdir()
    files = {"rules.json": [], "credentials.json": [], "grants.json": [],
             "identities.json": [{"private_ip": "127.0.0.1", "vm_id": "vm_test"}]}
    files.update(case.get("files") or {})
    for name, content in files.items():
        if content is not None:
            (config / name).write_text(content if isinstance(content, str) else json.dumps(content))

    services = {name: Recorder() for name in SERVICES}
    servers = [serve(make_handler(rec, "loopback"), port=FIXED_PORTS.get(name, 0)) for name, rec in services.items()]
    env = {k: v for k, v in os.environ.items() if k in ("PATH", "HOME", "LANG", "SSL_CERT_FILE")}
    env.update({
        "MITM_RULES_PATH": str(config / "rules.json"), "MITM_CREDENTIALS_PATH": str(config / "credentials.json"),
        "MITM_IDENTITIES_PATH": str(config / "identities.json"), "MITM_GRANTS_PATH": str(config / "grants.json"),
        "MITM_PENDING_PATH": str(config / "pending.jsonl"), "MITM_EXIT_PATH": str(config / "exit.json"),
        "MITM_LOG_FILE": str(logs / "traffic.jsonl"), "MITM_TENANT": "org_test",
    })
    for (name, rec), srv in zip(services.items(), servers):
        var, path = SERVICES[name]
        if var is None:
            if srv.server_address[1] != FIXED_PORTS[name]:
                raise RuntimeError(f"127.0.0.1:{FIXED_PORTS[name]} is taken: the {name} service needs it")
            continue
        env[var] = f"http://127.0.0.1:{srv.server_address[1]}{path}"
    env.update(case.get("env") or {})
    for name, paths in (case.get("loopback") or {}).items():
        for path, answers in paths.items():
            services[name].queue(path, answers)

    upstream_rec = Recorder()
    cert, key = upstream_cert()
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.load_cert_chain(cert, key)
    # Port 443 when this machine lets us bind it: a sign-in address names its port, and the
    # cases name none (`sysctl net.ipv4.ip_unprivileged_port_start=0`, or root as in the rig).
    up_srv = serve(make_handler(upstream_rec, "upstream"), own_address(), tls, 443)
    if up_srv.server_address[1] != 443 and case.get("needs_443"):
        up_srv.shutdown()
        raise RuntimeError("this case needs the upstream on port 443: run as root or lower net.ipv4.ip_unprivileged_port_start")
    upstream = (up_srv.server_address[0], up_srv.server_address[1])
    hosts = sorted({(s.get("request") or s.get("ws"))["host"] for s in case["steps"] if "request" in s or "ws" in s})
    if case.get("needs_hosts") and target == "mitmproxy":
        # The addon re-points a login swap at the name and resolves it itself: the names must
        # resolve to the upstream here (an /etc/hosts line, as the Docker rig writes).
        for h in hosts:
            try:
                if socket.gethostbyname(h) != upstream[0]:
                    raise OSError(h)
            except OSError:
                raise RuntimeError(f"{h} must resolve to {upstream[0]} for this case (add it to /etc/hosts)") from None
    proxy = Proxy(target, env, hosts, upstream, tmp)
    try:
        for i, step in enumerate(case["steps"]):
            name = step.get("name", f"step {i + 1}")
            try:
                run_step(step, proxy, upstream, services, upstream_rec, config, logs)
            except Mismatch as e:
                raise Mismatch(f"{name}: {e}") from None
    finally:
        proxy.stop()
        for s in servers + [up_srv]:
            s.shutdown()
        if not keep:
            shutil.rmtree(tmp, ignore_errors=True)
        else:
            print(f"    kept {tmp}")


def run_step(step, proxy, upstream, services, upstream_rec, config, logs):
    for fname, content in (step.get("files") or {}).items():
        content = expand(content)
        if content is None:
            (config / fname).unlink(missing_ok=True)
        else:
            bump(config / fname, content if isinstance(content, str) else json.dumps(content))
    for name, paths in (step.get("loopback") or {}).items():
        for path, answers in paths.items():
            services[name].queue(path, answers)
    if "upstream" in step:
        upstream_rec.queue("*", [step["upstream"]] if isinstance(step["upstream"], dict) else step["upstream"])
    before_calls = {n: len(r.calls) for n, r in services.items()}
    before_up = len(upstream_rec.calls)
    before_audit = len(lines(logs / "content-rules.jsonl"))
    before_traffic = len(lines(logs / "traffic.jsonl"))
    before_pending = len(lines(config / "pending.jsonl"))
    if "sleep" in step:
        time.sleep(step["sleep"])
    if "ws" in step:
        run_ws_step(step, proxy, upstream, services, upstream_rec, logs, before_calls, before_up, before_audit)
        return
    if "request" not in step:
        return
    t0 = time.time()
    status, headers, body = through_proxy(proxy, upstream, step["request"], step.get("timeout", 40))
    took = time.time() - t0
    exp = step.get("expect") or {}
    if "status" in exp and status != exp["status"]:
        raise Mismatch(f"status: want {exp['status']}, got {status}: {body[:300]!r}")
    for k, v in (exp.get("headers") or {}).items():
        got = headers.get(k.lower())
        if v == "$absent":
            if got is not None:
                raise Mismatch(f"header {k}: want absent, got {got!r}")
        elif got != v:
            raise Mismatch(f"header {k}: want {v!r}, got {got!r}")
    if "body" in exp and body.decode("utf-8", "replace") != exp["body"]:
        raise Mismatch(f"body: want {exp['body']!r}, got {body[:500]!r}")
    for key, exact in (("json", True), ("json_subset", False)):
        if key in exp:
            try:
                doc = json.loads(body)
            except ValueError:
                raise Mismatch(f"body is not JSON: {body[:300]!r}") from None
            match(exp[key], doc, "body", exact)
    if "body_contains" in exp:
        for piece in exp["body_contains"] if isinstance(exp["body_contains"], list) else [exp["body_contains"]]:
            if piece not in body.decode("utf-8", "replace"):
                raise Mismatch(f"body: {piece!r} not in {body[:500]!r}")
    if "max_seconds" in exp and took > exp["max_seconds"]:
        raise Mismatch(f"took {took:.1f}s, more than {exp['max_seconds']}s")
    if "min_seconds" in exp and took < exp["min_seconds"]:
        raise Mismatch(f"took {took:.1f}s, less than {exp['min_seconds']}s")

    # Fire-and-forget calls land after the answer: wait for the counts asked for, a little.
    want = exp.get("loopback") or {}
    deadline = time.time() + float(exp.get("settle", 1.5))
    while True:
        new = {n: [c for c in services[n].calls[before_calls[n]:]] for n in services}
        counts_ok = all(len([c for c in new[n] if c["path"].split("?", 1)[0] == p]) >= len(calls)
                        for n, paths in want.items() for p, calls in paths.items())
        audit_ok = "audit" not in exp or len(lines(logs / "content-rules.jsonl")) - before_audit >= len(exp["audit"])
        if (counts_ok and audit_ok) or time.time() > deadline:
            break
        time.sleep(0.05)
    time.sleep(float(exp.get("quiet", 0.3)))
    new = {n: services[n].calls[before_calls[n]:] for n in services}
    for n, paths in want.items():
        for p, calls in paths.items():
            got = [c for c in new[n] if c["path"].split("?", 1)[0] == p]
            if calls == "none":
                if got:
                    raise Mismatch(f"loopback {n} {p}: want no call, got {[c.get('json', c['body']) for c in got]}")
                continue
            if len(got) != len(calls):
                raise Mismatch(f"loopback {n} {p}: want {len(calls)} calls, got {[c.get('json', c['body']) for c in got]}")
            for j, (e, g) in enumerate(zip(calls, got)):
                match(e, g.get("json", g["body"]), f"loopback {n} {p}[{j}]", exact=False)
    if exp.get("no_loopback"):
        for n in exp["no_loopback"]:
            if new[n]:
                raise Mismatch(f"loopback {n}: want no call, got {[(c['path'], c.get('json')) for c in new[n]]}")

    up = upstream_rec.calls[before_up:]
    if "upstream" in exp:
        e = exp["upstream"]
        if e == "none":
            if up:
                raise Mismatch(f"upstream: want no request, got {[(c['method'], c['path']) for c in up]}")
        else:
            if len(up) != 1:
                raise Mismatch(f"upstream: want one request, got {len(up)}")
            got = up[0]
            for k in ("method", "path", "body"):
                if k in e and got[k] != e[k]:
                    raise Mismatch(f"upstream {k}: want {e[k]!r}, got {got[k]!r}")
            if "json" in e:
                match(e["json"], got.get("json"), "upstream json", True)
            if "json_subset" in e:
                match(e["json_subset"], got.get("json"), "upstream json", False)
            for k, v in (e.get("headers") or {}).items():
                gv = got["headers"].get(k.lower())
                if (v == "$absent" and gv is not None) or (v != "$absent" and gv != v):
                    raise Mismatch(f"upstream header {k}: want {v!r}, got {gv!r}")
            for piece in e.get("body_contains", []):
                if piece not in got["body"]:
                    raise Mismatch(f"upstream body: {piece!r} not in {got['body'][:300]!r}")
            for piece in e.get("body_lacks", []):
                if piece in got["body"]:
                    raise Mismatch(f"upstream body: {piece!r} must not be in {got['body'][:300]!r}")

    for key, path in (("audit", logs / "content-rules.jsonl"), ("traffic", logs / "traffic.jsonl")):
        if key in exp:
            got = lines(path)[before_audit if key == "audit" else before_traffic:]
            if len(got) != len(exp[key]):
                raise Mismatch(f"{key}: want {len(exp[key])} lines, got {got}")
            for j, (e, g) in enumerate(zip(exp[key], got)):
                match(e, g, f"{key}[{j}]", exact=False)
    if "pending" in exp:
        got = lines(config / "pending.jsonl")[before_pending:]
        if len(got) != len(exp["pending"]):
            raise Mismatch(f"pending: want {len(exp['pending'])} lines, got {got}")
        for j, (e, g) in enumerate(zip(exp["pending"], got)):
            match(e, g, f"pending[{j}]", exact=False)
    for piece in exp.get("audit_lacks", []):
        if piece in (logs / "content-rules.jsonl").read_text() if (logs / "content-rules.jsonl").exists() else False:
            raise Mismatch(f"audit: {piece!r} must not be in the audit file")


def run_ws_step(step, proxy, upstream, services, upstream_rec, logs, before_calls, before_up, before_audit):
    """A websocket step: `ws` opens it (host, path, headers, client `frames`), `upstream_ws` scripts
    the server (`frames` it sends after `delay`), and `expect` says what each side received."""
    upstream_rec.queue("*ws", [step.get("upstream_ws", {})])
    status, got = ws_through_proxy(proxy, upstream, step["ws"], step.get("timeout", 30))
    exp = step.get("expect") or {}
    if status != exp.get("status", 101):
        raise Mismatch(f"websocket status: want {exp.get('status', 101)}, got {status}")
    time.sleep(float(exp.get("quiet", 0.5)))
    if "client_received" in exp:
        match(exp["client_received"], [ws_doc(t) for t in got], "client received", exact=False)
    up = upstream_rec.calls[before_up:]
    if "server_received" in exp:
        if not up:
            raise Mismatch("upstream: no websocket reached it")
        match(exp["server_received"], [ws_doc(t) for t in up[-1].get("ws", [])], "server received", exact=False)
    if "upstream_headers" in exp:
        for k, v in exp["upstream_headers"].items():
            gv = up[-1]["headers"].get(k.lower()) if up else None
            if (v == "$absent" and gv is not None) or (v != "$absent" and gv != v):
                raise Mismatch(f"upstream header {k}: want {v!r}, got {gv!r}")
    new = {n: services[n].calls[before_calls[n]:] for n in services}
    for n, paths in (exp.get("loopback") or {}).items():
        for p, calls in paths.items():
            got_calls = [c for c in new[n] if c["path"].split("?", 1)[0] == p]
            if calls == "none":
                if got_calls:
                    raise Mismatch(f"loopback {n} {p}: want no call, got {[c.get('json') for c in got_calls]}")
                continue
            if len(got_calls) != len(calls):
                raise Mismatch(f"loopback {n} {p}: want {len(calls)} calls, got {[c.get('json') for c in got_calls]}")
            for j, (e, g) in enumerate(zip(calls, got_calls)):
                match(e, g.get("json", g["body"]), f"loopback {n} {p}[{j}]", exact=False)
    if "audit" in exp:
        got_audit = lines(logs / "content-rules.jsonl")[before_audit:]
        if len(got_audit) != len(exp["audit"]):
            raise Mismatch(f"audit: want {len(exp['audit'])} lines, got {got_audit}")
        for j, (e, g) in enumerate(zip(exp["audit"], got_audit)):
            match(e, g, f"audit[{j}]", exact=False)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("cases", nargs="*", default=[str(RUST / "conformance" / "cases" / "w2")])
    ap.add_argument("--target", choices=["mitmproxy", "cc-proxy"], default="mitmproxy")
    ap.add_argument("--filter")
    ap.add_argument("--keep", action="store_true", help="keep each case's folder (config, logs, proxy output)")
    args = ap.parse_args()
    files = []
    for c in args.cases:
        p = Path(c)
        files += sorted(p.glob("*.json")) if p.is_dir() else [p]
    passed = failed = skipped = 0
    for f in files:
        case = json.loads(f.read_text())
        # A step's files are expanded when the step runs: a lease's "$now" is then after the proxy started.
        case["steps"] = [{k: (v if k in ("expect", "files") else expand(v)) for k, v in st.items()} for st in case["steps"]]
        case["files"] = expand(case.get("files") or {})
        case["loopback"] = expand(case.get("loopback") or {})
        if args.filter and args.filter not in case["name"]:
            continue
        skip = (case.get("skip") or {}).get(args.target)
        need = case.get("addon_has")
        if not skip and args.target == "mitmproxy" and need and need not in ADDON.read_text():
            # A case for production's addon on main, newer than this branch's copy (set W2_ADDON).
            skip = f"this addon has no {need}; run with W2_ADDON=<main's addon.py>"
        if skip:
            skipped += 1
            print(f"skip  {case['name']} ({skip})")
            continue
        t0 = time.time()
        try:
            run_case(case, args.target, args.keep)
            passed += 1
            print(f"pass  {case['name']} ({time.time() - t0:.1f}s)")
        except Exception as e:  # noqa: BLE001 - a report, not a crash
            failed += 1
            print(f"FAIL  {case['name']}: {type(e).__name__}: {e}")
    print(f"\n{args.target}: {passed} passed, {failed} failed, {skipped} skipped")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
