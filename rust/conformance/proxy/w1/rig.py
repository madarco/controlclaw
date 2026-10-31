"""Wire-level proxy cases, run against mitmproxy 12.2.2 with addon.py or against cc-proxy.

    python3 rig.py --target mitmproxy|cc-proxy|both [--filter text] [case.yaml|folder ...]

Runs as root inside the rig image (run.sh builds it): it puts the fixture addresses on `lo`, names
in /etc/hosts and the origin CA in the system store, then for each case starts the proxy on a fresh
config folder, runs the steps and stops it. A case is only valid once it passes on mitmproxy; one
that passes there and fails on cc-proxy is a bug in cc-proxy. `skip: {cc-proxy: "P3"}` marks a gap
that is known and owned.

The case format is in README.md.
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import re
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import traceback
from pathlib import Path
from typing import Any

import yaml

import fixtures as fx

HERE = Path(__file__).resolve().parent
REPO = Path(os.environ.get("CC_REPO", HERE.parents[3]))
ADDON = Path(os.environ.get("CC_ADDON", REPO / "packages/mitm-proxy/addon.py"))
CC_PROXY = Path(os.environ.get("CC_PROXY_BIN", REPO / "rust/target/debug/cc-proxy"))
MITMDUMP = os.environ.get("CC_MITMDUMP", "mitmdump")
WORK = Path(os.environ.get("CC_RIG_WORK", "/tmp/cc-rig"))

# Names the origins answer to. Each resolves through /etc/hosts, the way a real name resolves
# through the firewall's DNS, so both proxies see the same answers.
HOSTS = {
    fx.ORIGIN_IP: ["origin.test", "www.origin.test", "cp.test", "backup.test", "bucket.s3.eu-west-1.amazonaws.com", "s3.eu-west-1.amazonaws.com", "login.tailscale.com",
                   "api.telegram.org", "slack.com", "pkgs.test", "other.test", "blocked.test",
                   "meet.turns.goog", "api.openai.com", "ai-gateway.vercel.sh", "openrouter.ai",
                   "api.anthropic.com", "secret.test", "api.agentmail.to", "api.twilio.com",
                   "residential.test", "res2.test", "ip.test"],
    fx.ORIGIN2_IP: ["origin2.test", "elsewhere.test"],
    "169.254.169.254": ["metadata.test"],
    "127.0.0.1": ["loopback.test"],
    "224.0.0.1": ["multicast.test"],
    "0.0.0.0": ["unspecified.test"],
    "::ffff:169.254.169.254": ["mapped.test"],
    "10.0.0.50": ["private.test"],
    fx.PROXY_IP: ["firewall.test"],
    fx.UPSTREAM_IP: ["upstream.test"],
}
# Names with more than one address: one line per address in /etc/hosts.
MULTI = {"mixed.test": [fx.ORIGIN_IP, "127.0.0.1"]}
# On the runner's `lo`. The proxy runs in its own network namespace (`px`), behind a veth pair, so
# none of these are its own addresses: it refuses to dial those.
ADDRESSES = [fx.ORIGIN_IP, fx.ORIGIN2_IP, fx.UPSTREAM_IP, fx.AGENT_IP, fx.AGENT2_IP, fx.UNKNOWN_IP]
NETNS = "px"
AGENTS = {"agent": fx.AGENT_IP, "agent2": fx.AGENT2_IP, "unknown": fx.UNKNOWN_IP}
PROXY_PORT = 8080


class CaseFailed(Exception):
    pass


# ---- one-time setup -----------------------------------------------------------------------------

def setup(root: Path) -> ssl.SSLContext:
    """Addresses, names, the origin CA in the system store, the proxy CA. Returns the origins' TLS."""
    for ip in ADDRESSES:
        subprocess.run(["ip", "addr", "add", f"{ip}/32", "dev", "lo"], capture_output=True)
    if not Path(f"/run/netns/{NETNS}").exists():
        for argv in (
            ["ip", "netns", "add", NETNS],
            ["ip", "link", "add", "rig0", "type", "veth", "peer", "name", "rig1"],
            ["ip", "link", "set", "rig1", "netns", NETNS],
            ["ip", "addr", "add", "10.0.0.1/24", "dev", "rig0"],
            ["ip", "link", "set", "rig0", "up"],
            ["ip", "netns", "exec", NETNS, "ip", "addr", "add", f"{fx.PROXY_IP}/24", "dev", "rig1"],
            ["ip", "netns", "exec", NETNS, "ip", "link", "set", "rig1", "up"],
            ["ip", "netns", "exec", NETNS, "ip", "link", "set", "lo", "up"],
            ["ip", "netns", "exec", NETNS, "ip", "route", "add", "default", "via", "10.0.0.1"],
        ):
            run(argv)
    # `ip netns exec` puts this over /etc/resolv.conf: the rig's own DNS stand-in (fixtures.NoRecords).
    Path(f"/etc/netns/{NETNS}").mkdir(parents=True, exist_ok=True)
    Path(f"/etc/netns/{NETNS}/resolv.conf").write_text("nameserver 10.0.0.1\noptions timeout:1 attempts:1\n")
    hosts = Path("/etc/hosts")
    text = hosts.read_text()
    if "# cc-rig" not in text:
        lines = ["# cc-rig"] + [f"{ip} {' '.join(names)}" for ip, names in HOSTS.items()]
        hosts.write_text(text.rstrip("\n") + "\n" + "\n".join(lines) + "\n")
        text = hosts.read_text()
    if "# cc-rig-multi" not in text:
        lines = ["# cc-rig-multi"] + [f"{ip} {name}" for name, ips in MULTI.items() for ip in ips]
        hosts.write_text(text.rstrip("\n") + "\n" + "\n".join(lines) + "\n")
    root.mkdir(parents=True, exist_ok=True)
    origin = root / "origin"
    origin.mkdir(exist_ok=True)
    if not (origin / "leaf.pem").exists():
        names = sorted({n for ns in HOSTS.values() for n in ns} | {"*.origin.test"})
        san = ",".join(f"DNS:{n}" for n in names) + f",IP:{fx.ORIGIN_IP},IP:{fx.ORIGIN2_IP}"
        run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "30",
             "-subj", "/CN=cc-rig origin CA", "-addext", "basicConstraints=critical,CA:TRUE",
             "-addext", "keyUsage=critical,keyCertSign,cRLSign",
             "-keyout", str(origin / "ca-key.pem"), "-out", str(origin / "ca.pem")])
        run(["openssl", "req", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=origin.test",
             "-keyout", str(origin / "leaf-key.pem"), "-out", str(origin / "leaf.csr")])
        (origin / "ext.cnf").write_text(f"subjectAltName={san}\nbasicConstraints=CA:FALSE\n"
                                        "extendedKeyUsage=serverAuth\n")
        run(["openssl", "x509", "-req", "-in", str(origin / "leaf.csr"), "-CA", str(origin / "ca.pem"),
             "-CAkey", str(origin / "ca-key.pem"), "-CAcreateserial", "-days", "30",
             "-extfile", str(origin / "ext.cnf"), "-out", str(origin / "leaf.pem")])
    system_ca = Path("/usr/local/share/ca-certificates/cc-rig-origin.crt")
    if not system_ca.exists():
        shutil.copy(origin / "ca.pem", system_ca)
        run(["update-ca-certificates"])
    ca = root / "ca"
    if not (ca / "mitmproxy-ca.pem").exists():
        run(["bash", str(REPO / "packages/mitm-proxy/gen-ca.sh"), str(ca)])
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(origin / "leaf.pem", origin / "leaf-key.pem")
    ctx.set_alpn_protocols(["http/1.1"])

    def remember_sni(obj, name, _ctx):
        try:
            obj.rig_sni = name
        except AttributeError:
            pass
    ctx.sni_callback = remember_sni
    return ctx


def run(argv: list[str]) -> None:
    subprocess.run(argv, check=True, capture_output=True)


# ---- the proxy ----------------------------------------------------------------------------------

class Proxy:
    def __init__(self, target: str, case: dict[str, Any], root: Path, rig: Path):
        self.target = target
        self.root = root
        self.config = root / "config"
        self.config.mkdir(parents=True)
        self.logs = root / "logs"
        self.logs.mkdir()
        # What the agent writes on every box; the addon refuses every request body without it.
        # rules.json too: the agent writes it at its first sync, and cc-proxy refuses everything
        # until it has read one (`rules.json: null` in a case leaves it out).
        files = {"content-rules.json": {"version": 1, "rules": []}, "rules.json": []}
        files.update(case.get("files") or {})
        for name, content in files.items():
            if content is not None:
                write_file(self.config / name, content)
        env = {
            "PATH": os.environ["PATH"],
            "HOME": str(root),
            "MITM_RULES_PATH": str(self.config / "rules.json"),
            "MITM_CREDENTIALS_PATH": str(self.config / "credentials.json"),
            "MITM_IDENTITIES_PATH": str(self.config / "identities.json"),
            "MITM_GRANTS_PATH": str(self.config / "grants.json"),
            "MITM_PENDING_PATH": str(self.config / "pending.jsonl"),
            "MITM_EXIT_PATH": str(self.config / "exit.json"),
            "MITM_LOG_FILE": str(self.logs / "traffic.jsonl"),
            "MITM_TENANT": "rig-org",
            "MITM_CONTROL_PLANE_HOST": "cp.test",
            "MITM_BACKUP_HOST": "bucket.s3.eu-west-1.amazonaws.com",
            "MITM_UPDATE_HOSTS": "pkgs.test",
            "MITM_DEV_LOG_SECRETS": "0", "MITM_DEV_ALLOW_PLAINTEXT_STORE": "0",
            "MITM_DEV_INSECURE_UPSTREAM": "0", "MITM_DEV_ALLOW_DIRECT_EGRESS": "0",
            # The origins are on documentation addresses, which are not public: passthrough may
            # reach them only with the rigs' switch (#511 has the same one).
            "MITM_DEV_PRIVATE_PASSTHROUGH": "1", "MITM_ALLOW_DEV_FLAGS": "1",
            # cc-proxy refuses intercepted traffic while W2's checks are not built in.
            "MITM_DEV_WITHOUT_CHECKS": "1",
            "RUST_LOG": os.environ.get("RUST_LOG", "info"),
        }
        env.update({k: str(v) for k, v in (case.get("env") or {}).items()})
        self.env = env
        self.ca = rig / "ca"
        addon = ADDON
        if target == "mitmproxy" and env.get("MITM_DEV_MEET_RANGES"):
            # The addon's Meet TURN ranges are Google's only; cc-proxy takes the rig's range from
            # MITM_DEV_MEET_RANGES, and a copy of the addon gets the same added here.
            addon = root / "addon.py"
            text = ADDON.read_text()
            anchor = "MEETING_MAX_BYTES = "
            extra = ("for _sni, _net in (e.split('=', 1) for e in os.environ['MITM_DEV_MEET_RANGES'].split(',')):\n"
                     "    MEETING_MEDIA_RANGES[_sni] = MEETING_MEDIA_RANGES.get(_sni, ()) + (ipaddress.ip_network(_net),)\n")
            addon.write_text(text.replace(anchor, extra + anchor, 1))
        if target == "mitmproxy":
            # As the unit runs it (controlclaw-ansible tasks/mitmbox.yml), plus the rig's origin CA.
            argv = [MITMDUMP, "--listen-port", str(PROXY_PORT),
                    "--ignore-hosts", f"^{re.escape(env['MITM_CONTROL_PLANE_HOST'])}:[0-9]+$",
                    "--set", "flow_detail=0", "--set", "connection_strategy=lazy",
                    "--set", f"confdir={self.ca}",
                    "--set", f"ssl_verify_upstream_trusted_ca={rig / 'origin/ca.pem'}",
                    "-s", str(addon)]
        else:
            env["MITM_CA_DIR"] = str(self.ca)
            argv = [str(CC_PROXY), "--listen", f"0.0.0.0:{PROXY_PORT}"]
        self.out = open(root / "proxy.log", "wb")
        argv = ["ip", "netns", "exec", NETNS] + argv
        self.proc = subprocess.Popen(argv, env=env, stdout=self.out, stderr=subprocess.STDOUT, cwd=root)

    def wait_ready(self) -> bool:
        for _ in range(300):
            if self.proc.poll() is not None:
                return False
            try:
                socket.create_connection((fx.PROXY_IP, PROXY_PORT), timeout=1).close()
                return True
            except OSError:
                time.sleep(0.05)
        raise CaseFailed("proxy did not listen")

    def wait_exit(self, timeout: float) -> int | None:
        try:
            return self.proc.wait(timeout)
        except subprocess.TimeoutExpired:
            return None

    def output(self) -> str:
        self.out.flush()
        return (self.root / "proxy.log").read_text(errors="replace")

    def stop(self) -> None:
        if self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(10)
            except subprocess.TimeoutExpired:
                self.proc.kill()
        self.out.close()


def timed(value: Any) -> Any:
    """`"$now"` and `"$now+30"` / `"$now-5"` in a file's values: the time it is written, as a number."""
    if isinstance(value, dict):
        return {k: timed(v) for k, v in value.items()}
    if isinstance(value, list):
        return [timed(v) for v in value]
    m = re.fullmatch(r"\$now([+-][0-9.]+)?", value) if isinstance(value, str) else None
    return time.time() + float(m.group(1) or 0) if m else value


def write_file(path: Path, content: Any) -> None:
    content = timed(content)
    if isinstance(content, str):
        path.write_text(content)
    else:
        path.write_text(json.dumps(content))


# ---- the client: an agent box behind redsocks ---------------------------------------------------

def resolve(host: str) -> str:
    """What the agent box's own resolver says, as redsocks would put it in the CONNECT."""
    for ip, names in HOSTS.items():
        if host in names:
            return ip
    return host


def dial(agent: str) -> socket.socket:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(8)
    s.bind((AGENTS[agent], 0))
    s.connect((fx.PROXY_IP, PROXY_PORT))
    return s


def connect(agent: str, target: str) -> tuple[socket.socket, bytes]:
    """CONNECT, as redsocks sends it. Returns the socket and the proxy's answer head."""
    s = dial(agent)
    s.sendall(f"CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n".encode())
    head = bytearray()
    while not head.endswith(b"\r\n\r\n"):
        chunk = s.recv(1)
        if not chunk:
            break
        head.extend(chunk)
    return s, bytes(head)


def tls_wrap(s: socket.socket, sni: str | None, trust: str, rig: Path, alpn: list[str] | None = None) -> ssl.SSLSocket:
    """`trust: mitm` accepts only the proxy's CA (so the flow was intercepted), `origin` only the
    origin's (so it was passed through untouched)."""
    cafile = rig / ("ca/ca-cert.pem" if trust == "mitm" else "origin/ca.pem")
    ctx = ssl.create_default_context(cafile=str(cafile))
    if not sni:
        ctx.check_hostname = False
    if alpn:
        ctx.set_alpn_protocols(alpn)
    return ctx.wrap_socket(s, server_hostname=sni)


def read_response(s: socket.socket, method: str = "GET") -> dict[str, Any]:
    """One HTTP/1.1 response (Content-Length, chunked, or until close)."""
    buf = bytearray()
    while b"\r\n\r\n" not in buf:
        chunk = s.recv(65536)
        if not chunk:
            if not buf:
                raise ConnectionError("closed before a response")
            break
        buf.extend(chunk)
    head, _, rest = bytes(buf).partition(b"\r\n\r\n")
    lines = head.decode("latin-1").split("\r\n")
    status = int(lines[0].split(" ")[1])
    headers: dict[str, str] = {}
    for line in lines[1:]:
        k, _, v = line.partition(":")
        headers[k.strip().lower()] = v.strip()
    body = bytearray(rest)
    if method == "HEAD" or status in (204, 304):
        pass
    elif headers.get("transfer-encoding", "").lower() == "chunked":
        data = bytes(body)
        while not data.endswith(b"0\r\n\r\n"):
            chunk = s.recv(65536)
            if not chunk:
                break
            data += chunk
        out = bytearray()
        while data:
            size_line, _, data = data.partition(b"\r\n")
            size = int(size_line.split(b";")[0] or b"0", 16)
            if size == 0:
                break
            out.extend(data[:size])
            data = data[size + 2:]
        body = out
    elif "content-length" in headers:
        want = int(headers["content-length"])
        while len(body) < want:
            chunk = s.recv(65536)
            if not chunk:
                break
            body.extend(chunk)
    else:
        while chunk := s.recv(65536):
            body.extend(chunk)
    return {"status": status, "headers": headers, "body": bytes(body)}


def h2_request(s: ssl.SSLSocket, method: str, authority: str, path: str, headers: dict[str, str],
               body: bytes) -> dict[str, Any]:
    """One request on a fresh h2 connection."""
    import h2.connection
    import h2.events
    conn = h2.connection.H2Connection()
    conn.initiate_connection()
    hdrs = [(":method", method), (":scheme", "https"), (":authority", authority), (":path", path)]
    hdrs += [(k.lower(), v) for k, v in headers.items()]
    conn.send_headers(1, hdrs, end_stream=not body)
    if body:
        conn.send_data(1, body, end_stream=True)
    s.sendall(conn.data_to_send())
    status, out_headers, data = 0, {}, bytearray()
    while True:
        chunk = s.recv(65536)
        if not chunk:
            raise ConnectionError("h2 connection closed")
        for ev in conn.receive_data(chunk):
            if isinstance(ev, h2.events.ResponseReceived):
                for k, v in ev.headers:
                    k, v = k.decode(), v.decode()
                    if k == ":status":
                        status = int(v)
                    else:
                        out_headers[k] = v
            elif isinstance(ev, h2.events.DataReceived):
                data.extend(ev.data)
                conn.acknowledge_received_data(ev.flow_controlled_length, ev.stream_id)
            elif isinstance(ev, h2.events.StreamReset):
                raise ConnectionError(f"stream reset {ev.error_code}")
            elif isinstance(ev, h2.events.StreamEnded):
                return {"status": status, "headers": out_headers, "body": bytes(data)}
        s.sendall(conn.data_to_send())


# ---- matching ------------------------------------------------------------------------------------

UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")


def match(expected: Any, actual: Any, path: str = "$") -> None:
    """`expected` is a subset of `actual` for objects; lists match item by item and in length.
    Matchers: `$any`, `$absent` (key must not be there), `$null`, `$number`, `$string`, `$uuid`,
    `$contains:<text>`, `$re:<pattern>`."""
    if isinstance(expected, str) and expected.startswith("$"):
        ok = {
            "$any": True,
            "$null": actual is None,
            "$number": isinstance(actual, (int, float)) and not isinstance(actual, bool),
            "$string": isinstance(actual, str),
            "$uuid": isinstance(actual, str) and bool(UUID.match(actual)),
        }.get(expected)
        if ok is None and expected.startswith("$contains:"):
            ok = isinstance(actual, str) and expected[len("$contains:"):] in actual
        if ok is None and expected.startswith("$re:"):
            ok = isinstance(actual, str) and re.search(expected[4:], actual) is not None
        if ok is None and expected == "$absent":
            raise CaseFailed(f"{path}: should be absent, is {actual!r}")
        if not ok:
            raise CaseFailed(f"{path}: {actual!r} does not match {expected}")
        return
    if isinstance(expected, dict):
        if not isinstance(actual, dict):
            raise CaseFailed(f"{path}: expected an object, got {actual!r}")
        for k, v in expected.items():
            if v == "$absent":
                if k in actual:
                    raise CaseFailed(f"{path}.{k}: should be absent, is {actual[k]!r}")
                continue
            if k not in actual:
                raise CaseFailed(f"{path}.{k}: missing in {json.dumps(actual)[:400]}")
            match(v, actual[k], f"{path}.{k}")
        return
    if isinstance(expected, list):
        if not isinstance(actual, list) or len(actual) != len(expected):
            raise CaseFailed(f"{path}: expected {len(expected)} items, got {json.dumps(actual)[:600]}")
        for i, (e, a) in enumerate(zip(expected, actual)):
            match(e, a, f"{path}[{i}]")
        return
    if expected != actual:
        raise CaseFailed(f"{path}: expected {expected!r}, got {actual!r}")


# ---- steps --------------------------------------------------------------------------------------

class Runner:
    def __init__(self, fixtures: fx.Fixtures, rig: Path):
        self.fx = fixtures
        self.rig = rig

    def run_case(self, case: dict[str, Any], target: str) -> None:
        root = WORK / f"{target}-{re.sub(r'[^a-z0-9]+', '-', case['name'].lower())[:60]}"
        shutil.rmtree(root, ignore_errors=True)
        root.mkdir(parents=True)
        self.fx.reset()
        proxy = Proxy(target, case, root, self.rig)
        self.proxy = proxy
        try:
            start = case.get("start")
            if start is not None:
                code = proxy.wait_exit(15)
                if start.get("refused"):
                    if code in (None, 0):
                        raise CaseFailed(f"proxy did not refuse to start (exit {code})")
                    want = start.get("output_contains")
                    if want and want not in proxy.output():
                        raise CaseFailed(f"start output lacks {want!r}:\n{proxy.output()[-2000:]}")
                    return
            if not proxy.wait_ready():
                raise CaseFailed(f"proxy exited:\n{proxy.output()[-3000:]}")
            # mitmproxy reads its addon after it listens; give both a moment to settle.
            time.sleep(0.3)
            for i, step in enumerate(case["steps"]):
                try:
                    self.step(step)
                except CaseFailed as e:
                    raise CaseFailed(f"step {i + 1} ({step.get('name') or next(iter(step))}): {e}") from None
                except Exception as e:  # noqa: BLE001
                    raise CaseFailed(f"step {i + 1} ({step.get('name') or next(iter(step))}): "
                                     f"{type(e).__name__}: {e}") from None
        except CaseFailed:
            if os.environ.get("CC_RIG_SHOW_LOG"):
                print(proxy.output()[-4000:], file=sys.stderr)
            raise
        finally:
            proxy.stop()

    def step(self, step: dict[str, Any]) -> None:
        kind = next(k for k in step if k not in ("name", "expect"))
        getattr(self, "step_" + kind)(step[kind], step.get("expect") or {})

    # A raw byte exchange through CONNECT: what test_tcp_drop.py's probe does.
    def step_raw(self, spec: dict[str, Any], expect: dict[str, Any]) -> None:
        s, head = connect(spec.get("agent", "agent"), spec["connect"])
        try:
            if b" 200 " not in head.split(b"\r\n")[0] + b" ":
                raise CaseFailed(f"CONNECT answered {head!r}")
            if spec.get("tls"):
                s = tls_wrap(s, spec.get("sni"), spec["tls"], self.rig)
            if spec.get("then_write"):
                # Changed while the connection is open: a lease revoked under a live relay.
                self.step_write(spec["then_write"], {})
            payload = spec.get("send", "").encode() if "send" in spec else bytes.fromhex(spec.get("send_hex", ""))
            got = bytearray()
            closed = False
            if expect.get("timeout"):
                s.settimeout(1.5)
                try:
                    chunk = s.recv(1)
                except (TimeoutError, socket.timeout):
                    return
                raise CaseFailed(f"expected nothing, got {chunk!r}")
            try:
                if payload:
                    s.sendall(payload)
                if "recv" in expect:
                    want = expect["recv"].encode("latin-1") if isinstance(expect["recv"], str) else bytes(expect["recv"])
                    want = want.replace(b"<greeting>", fx.GREETING)
                    while len(got) < len(want):
                        chunk = s.recv(65536)
                        if not chunk:
                            closed = True
                            break
                        got.extend(chunk)
                else:
                    chunk = s.recv(65536)
                    got.extend(chunk)
                    closed = not chunk
            except (ConnectionResetError, BrokenPipeError, ssl.SSLError, TimeoutError, socket.timeout) as e:
                closed = not isinstance(e, (TimeoutError, socket.timeout))
                if not closed:
                    raise CaseFailed("no answer and no close within the timeout") from None
            if "recv" in expect:
                want = expect["recv"].encode("latin-1").replace(b"<greeting>", fx.GREETING)
                if bytes(got) != want:
                    raise CaseFailed(f"received {bytes(got)!r}, expected {want!r}")
            if expect.get("closed"):
                if got:
                    raise CaseFailed(f"client received bytes: {bytes(got)!r}")
                if not closed:
                    raise CaseFailed("connection stayed open")
        finally:
            s.close()

    # One CONNECT, then nothing: for checking what a connection with no bytes does.
    def step_connect(self, spec: dict[str, Any], expect: dict[str, Any]) -> None:
        s, head = connect(spec.get("agent", "agent"), spec["target"])
        s.close()
        if "status" in expect:
            status = int(head.split(b" ")[1]) if head else None
            if status != expect["status"]:
                raise CaseFailed(f"CONNECT answered {head!r}")

    def step_http(self, spec: dict[str, Any], expect: dict[str, Any]) -> None:
        url = spec["url"]
        scheme, _, rest = url.partition("://")
        authority, slash, path = rest.partition("/")
        path = slash + path or "/"
        host, _, port = authority.partition(":")
        port = int(port or (443 if scheme == "https" else 80))
        method = spec.get("method", "GET")
        body = spec.get("body", "")
        if isinstance(body, (dict, list)):
            body = json.dumps(body)
        body_b = body.encode() if isinstance(body, str) else body
        if "body_bytes" in spec:
            # A big upload, counted by the origin (`x-rig-sink`) rather than echoed back.
            body_b = b"x" * int(spec["body_bytes"])
            spec = {**spec, "headers": {**(spec.get("headers") or {}), "x-rig-sink": "1"}}
        headers = {"Host": spec.get("host_header", authority)}
        headers.update(spec.get("headers") or {})
        if "respond" in spec:
            headers["x-rig-respond"] = base64.b64encode(json.dumps(spec["respond"]).encode()).decode()
        if body_b or method in ("POST", "PUT", "PATCH"):
            headers.setdefault("Content-Length", str(len(body_b)))
        headers.setdefault("Connection", "close")
        agent = spec.get("agent", "agent")
        try:
            if spec.get("via", "connect") == "absolute":
                s = dial(agent)
                target = url
            else:
                s, head = connect(agent, spec.get("connect", f"{resolve(host)}:{port}"))
                if b" 200 " not in head.split(b"\r\n")[0] + b" ":
                    raise CaseFailed(f"CONNECT answered {head!r}")
                if scheme == "https":
                    alpn = ["h2"] if spec.get("h2") else None
                    s = tls_wrap(s, spec.get("sni", host), spec.get("trust", "mitm"), self.rig, alpn)
                    if spec.get("h2"):
                        if s.selected_alpn_protocol() != "h2":
                            raise CaseFailed(f"ALPN {s.selected_alpn_protocol()!r}, expected h2")
                        headers.pop("Connection", None)
                        authority_h = headers.pop("Host")
                        res = h2_request(s, method, authority_h, path, headers, body_b)
                        s.close()
                        self.check_http(res, expect)
                        return
                target = path
            extra = "".join(f"{k}: {v}\r\n" for k, v in spec.get("extra_headers", []))
            req = f"{method} {target} HTTP/1.1\r\n" + "".join(f"{k}: {v}\r\n" for k, v in headers.items()) + extra + "\r\n"
            try:
                s.sendall(req.encode("latin-1") + body_b)
            except (ConnectionError, ssl.SSLError, OSError):
                # The proxy may answer before the body is all sent (a 413) and close: its answer
                # is still there to read.
                pass
            res = read_response(s, method)
            s.close()
        except (ConnectionError, ssl.SSLError, OSError) as e:
            if expect.get("error"):
                return
            raise CaseFailed(f"request failed: {type(e).__name__}: {e}") from None
        if expect.get("error"):
            raise CaseFailed(f"expected the request to fail, got {res['status']}")
        self.check_http(res, expect)

    def check_http(self, res: dict[str, Any], expect: dict[str, Any]) -> None:
        self.last = res
        if "status" in expect and res["status"] != expect["status"]:
            raise CaseFailed(f"status {res['status']}, expected {expect['status']}: {res['body'][:300]!r}")
        if "headers" in expect:
            match(expect["headers"], res["headers"], "$headers")
        if "json" in expect:
            match(expect["json"], json.loads(res["body"] or b"null"), "$body")
        if "body" in expect and res["body"].decode("utf-8", "replace") != expect["body"]:
            raise CaseFailed(f"body {res['body'][:300]!r}")
        if "body_len" in expect and len(res["body"]) != int(expect["body_len"]):
            raise CaseFailed(f"body of {len(res['body'])} bytes, expected {expect['body_len']}")
        if "body_contains" in expect and expect["body_contains"] not in res["body"].decode("utf-8", "replace"):
            raise CaseFailed(f"body lacks {expect['body_contains']!r}: {res['body'][:300]!r}")

    def step_log(self, spec: dict[str, Any], _expect: dict[str, Any]) -> None:
        """The traffic records written so far (optionally only those matching `where`), checked as
        a list: `records` all of them in order, or `last` the last one."""
        deadline = time.time() + float(spec.get("within", 2))
        while True:
            try:
                records = self.records(spec.get("file", "traffic.jsonl"))
                where = spec.get("where")
                if where:
                    records = [r for r in records if all(r.get(k) == v for k, v in where.items())]
                if "records" in spec:
                    match(spec["records"], records, "$records")
                if "last" in spec:
                    if not records:
                        raise CaseFailed("no records")
                    match(spec["last"], records[-1], "$last")
                if "count" in spec and len(records) != spec["count"]:
                    raise CaseFailed(f"{len(records)} records, expected {spec['count']}: {records}")
                return
            except CaseFailed:
                if time.time() > deadline:
                    raise
                time.sleep(0.1)

    def records(self, name: str) -> list[dict[str, Any]]:
        path = (self.proxy.config if name == "pending.jsonl" else self.proxy.logs) / name
        if not path.exists():
            return []
        return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]

    def step_seen(self, spec: dict[str, Any], _expect: dict[str, Any]) -> None:
        """What a fixture saw: `connections`, `received` (text), `requests` (count), `last` (subset
        of the last request), `upstream` (request lines an upstream proxy got)."""
        seen = self.fx.seen(spec.get("server", "origin"))
        if "connections" in spec and seen.connections != spec["connections"]:
            raise CaseFailed(f"{seen.connections} connections, expected {spec['connections']}")
        if "received" in spec and bytes(seen.received) != spec["received"].encode("latin-1"):
            raise CaseFailed(f"received {bytes(seen.received)!r}")
        if "requests" in spec and len(seen.requests) != spec["requests"]:
            raise CaseFailed(f"{len(seen.requests)} requests, expected {spec['requests']}: {seen.requests}")
        if "last" in spec:
            if not seen.requests:
                raise CaseFailed("no requests")
            match(spec["last"], seen.requests[-1], "$last")
        if "upstream" in spec:
            match(spec["upstream"], list(seen.upstream), "$upstream")

    def step_ws(self, spec: dict[str, Any], expect: dict[str, Any]) -> None:
        """A websocket through the proxy: `url` (wss:// or ws://), `send` (texts, or {binary: hex}),
        offering permessage-deflate as browsers do. Expect `status` (of the handshake), `recv` (the
        texts that come back, in order), `closed` (the site or the proxy closed it)."""
        import wsproto
        import wsproto.events as ev
        from wsproto.extensions import PerMessageDeflate
        url = spec["url"]
        scheme, _, rest = url.partition("://")
        authority, slash, path = rest.partition("/")
        host, _, port = authority.partition(":")
        port = int(port or (443 if scheme == "wss" else 80))
        s, head = connect(spec.get("agent", "agent"), spec.get("connect", f"{resolve(host)}:{port}"))
        if scheme == "wss":
            s = tls_wrap(s, spec.get("sni", host), spec.get("trust", "mitm"), self.rig, ["http/1.1"])
        s.settimeout(5)
        ws = wsproto.WSConnection(wsproto.ConnectionType.CLIENT)
        s.sendall(ws.send(ev.Request(host=spec.get("host_header", authority), target="/" + path,
                                     extensions=[PerMessageDeflate()])))
        got, status, closed = [], None, False
        want = len(expect.get("recv", []))

        def pump_events():
            nonlocal status, closed
            for e in ws.events():
                if isinstance(e, ev.AcceptConnection):
                    status = 101
                elif isinstance(e, ev.RejectConnection):
                    status = e.status_code
                elif isinstance(e, ev.TextMessage):
                    got.append(e.data)
                elif isinstance(e, ev.BytesMessage):
                    got.append({"binary": bytes(e.data).hex()})
                elif isinstance(e, ev.CloseConnection):
                    closed = True
                    try:
                        s.sendall(ws.send(e.response()))
                    except (OSError, wsproto.utilities.LocalProtocolError):
                        pass
        try:
            while status is None:
                data = s.recv(65536)
                if not data:
                    break
                ws.receive_data(data)
                pump_events()
            if status == 101:
                for m in spec.get("send", []):
                    if isinstance(m, dict):
                        s.sendall(ws.send(ev.Message(data=bytes.fromhex(m["binary"]))))
                    else:
                        s.sendall(ws.send(ev.Message(data=m)))
                while len(got) < want or (expect.get("closed") and not closed):
                    data = s.recv(65536)
                    if not data:
                        closed = True
                        break
                    ws.receive_data(data)
                    pump_events()
        except (TimeoutError, socket.timeout):
            pass
        except (OSError, ssl.SSLError):
            closed = True
        finally:
            s.close()
        if "status" in expect and status != expect["status"]:
            raise CaseFailed(f"handshake status {status}, expected {expect['status']}")
        if "recv" in expect:
            match(expect["recv"], got, "$recv")
        if expect.get("closed") and not closed:
            raise CaseFailed("the websocket stayed open")

    def step_write(self, spec: dict[str, Any], _expect: dict[str, Any]) -> None:
        path = self.proxy.config / spec["file"]
        write_file(path, spec["content"])
        # A new mtime even within one second, as the agent's rename gives.
        later = time.time() + float(spec.get("mtime_offset", 2))
        os.utime(path, (later, later))

    def step_upstream(self, spec: dict[str, Any], _expect: dict[str, Any]) -> None:
        """Check the credentials the upstream got (`auths`), or set the password it wants."""
        if "password" in spec:
            self.fx.upstream.password = spec["password"]
        if "auths" in spec:
            match(spec["auths"], list(self.fx.upstream.auths), "$auths")

    def step_judge(self, spec: dict[str, Any], _expect: dict[str, Any]) -> None:
        if "answer" in spec:
            self.fx.judge.answer = spec["answer"]
        if "delay" in spec:
            self.fx.judge.delay = float(spec["delay"])

    def step_sleep(self, spec: Any, _expect: dict[str, Any]) -> None:
        time.sleep(float(spec))

    def step_output(self, spec: dict[str, Any], _expect: dict[str, Any]) -> None:
        out = self.proxy.output()
        for text in spec.get("lacks", []):
            if text in out:
                raise CaseFailed(f"proxy output contains {text!r}")


# ---- main ---------------------------------------------------------------------------------------

def collect(paths: list[str]) -> list[Path]:
    out: list[Path] = []
    for p in map(Path, paths):
        if p.is_dir():
            out += sorted(p.rglob("*.yaml"))
        else:
            out.append(p)
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("cases", nargs="*", default=[str(HERE / "cases")])
    ap.add_argument("--target", choices=["mitmproxy", "cc-proxy", "both"], default="both")
    ap.add_argument("--filter")
    args = ap.parse_args()
    rig = WORK / "rig"
    fixtures = fx.Fixtures(setup(rig))
    runner = Runner(fixtures, rig)
    targets = ["mitmproxy", "cc-proxy"] if args.target == "both" else [args.target]
    passed = failed = skipped = 0
    print(f"{'case':<70} {'mitmproxy':<14} {'cc-proxy':<14}")
    for path in collect(args.cases):
        for case in yaml.safe_load_all(path.read_text()):
            if not case:
                continue
            if args.filter and args.filter not in case["name"]:
                continue
            cols, errors = [], []
            for t in ["mitmproxy", "cc-proxy"]:
                if t not in targets:
                    cols.append("-")
                    continue
                why = (case.get("skip") or {}).get(t)
                if why:
                    skipped += 1
                    cols.append(f"skip ({why})")
                    continue
                try:
                    runner.run_case(case, t)
                    passed += 1
                    cols.append("pass")
                except CaseFailed as e:
                    failed += 1
                    cols.append("FAIL")
                    errors.append(f"[{t}] {case['name']}: {e}")
                except Exception:  # noqa: BLE001
                    failed += 1
                    cols.append("FAIL")
                    errors.append(f"[{t}] {case['name']}: {traceback.format_exc()}")
            print(f"{case['name'][:70]:<70} {cols[0]:<14} {cols[1]:<14}", flush=True)
            for e in errors:
                print("   " + e.replace("\n", "\n   "), file=sys.stderr, flush=True)
    print(f"\n{passed} passed, {failed} failed, {skipped} skipped")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
