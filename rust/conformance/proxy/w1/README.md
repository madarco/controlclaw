# W1 proxy cases

Wire-level cases for the egress proxy, run against **mitmproxy 12.2.2 with `addon.py`** and against
**cc-proxy** (docs/plans/rust-rewrite.md §4.2, "Proxy conformance"). A case counts once it passes on
mitmproxy; one that passes there and fails on cc-proxy is a bug in cc-proxy.

```bash
rust/conformance/proxy/w1/run.sh                                  # every case, both proxies
rust/conformance/proxy/w1/run.sh --target cc-proxy --filter drop  # one proxy, some cases
CC_RIG_SHOW_LOG=1 rust/conformance/proxy/w1/run.sh ...            # print the proxy's log on a failure
```

`run.sh` builds cc-proxy (debug, static musl: needs `musl-gcc`) and the rig image (`Dockerfile`: Ubuntu 24.04, mitmproxy 12.2.2 in a
venv as the role installs it), then runs `rig.py` in a container with the repository mounted. The
container needs `NET_ADMIN` and `SYS_ADMIN`: the runner puts the fixture addresses on `lo` and runs the
proxy in its own network namespace (`px`, behind a veth pair), so none of the fixtures are on the
proxy's own interfaces, which it refuses to dial.

These cases live here rather than in `rust/conformance/cases/w1/` until `cc-conformance` takes
`--target mitmproxy|cc-proxy` (a W0 item): its runner reads every YAML file under `cases/` as an
agent case.

## The rig

| What | Where |
| --- | --- |
| The proxy | `10.0.0.2:8080` in the `px` namespace (`firewall.test` names it), on a fresh config folder per case, with the unit's environment (`MITM_*`, control plane `cp.test`, backup `backup.test`, update hosts `pkgs.test`) |
| Agents | `10.0.0.3` (`agent`), `10.0.0.4` (`agent2`), `10.0.0.9` (`unknown`, in no identity map) |
| Origins | `203.0.113.10` and `.11`: HTTP reflector on 80, TLS reflector on 443 and 8443, raw echo that speaks first on 7000, TLS echo on 7443 |
| Names | `/etc/hosts` (see `HOSTS` in `rig.py`): `origin.test`, `cp.test`, `api.openai.com`, ... on the origins; `metadata.test` on 169.254.169.254, `loopback.test` on 127.0.0.1, ... |
| TLS | the proxy CA from `packages/mitm-proxy/gen-ca.sh`; the origins' own CA in the system store (cc-proxy) and in `ssl_verify_upstream_trusted_ca` (mitmproxy) |
| Judge | the firewall agent's `127.0.0.1:3101/judge` on the proxy's loopback, answering what a `judge` step set |

The origins are on documentation ranges (203.0.113.0/24, 198.51.100.0/24), which are not public
(Python's `is_global`). Passthrough reaches them only with `MITM_DEV_PRIVATE_PASSTHROUGH=1` (and
`MITM_ALLOW_DEV_FLAGS=1`), which the rig sets for both proxies, as #511's smoke rigs do.

## A case

One YAML document per case (several per file, separated by `---`):

```yaml
name: raw TCP after CONNECT is dropped and recorded
files:                         # into the config folder, as the agent would write them
  rules.json: []
  identities.json: [{private_ip: 10.0.0.3, vm_id: test-agent}]
env: {MITM_DEV_LOG_SECRETS: "1"}  # over the unit's environment
start: {refused: true, output_contains: "..."}  # the proxy must not start
skip: {cc-proxy: P3}           # a known, owned gap on one proxy
steps:
  - raw: {connect: "203.0.113.10:7000", tls: mitm|origin, sni: origin.test, send: "text", send_hex: "00ff", agent: agent}
    expect: {closed: true} | {recv: "<greeting>text"}
  - connect: {target: "203.0.113.10:7000"}
    expect: {status: 200}
  - http: {url: "https://origin.test/x", method: POST, headers: {}, body: "..." | {json},
           via: connect|absolute, connect: "ip:port", sni: name, host_header: name, trust: mitm|origin,
           respond: {status: 402, headers: {}, body: "..."}}   # what the origin answers
    expect: {status: 200, json: {...}, headers: {...}, body: "...", body_contains: "...", error: true}
  - log: {records: [...] | last: {...} | count: n, where: {effect: drop}, file: traffic.jsonl|pending.jsonl, within: 2}
  - seen: {server: origin|echo|judge, connections: 0, requests: 1, received: "", last: {...}}
  - write: {file: identities.json, content: [...]}   # "$now", "$now+30": the time it is written
  # raw also takes then_write: {file, content}, written after the TLS handshake
  - judge: {answer: {decision: block}, delay: 0.5}
  - sleep: 0.5
```

Expected values are subsets for objects and exact for lists and scalars. Matchers: `$any`,
`$absent`, `$null`, `$number`, `$string`, `$uuid`, `$contains:<text>`, `$re:<pattern>`.
