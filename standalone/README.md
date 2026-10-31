# The firewall without our Ansible

Two ways to run the ControlClaw firewall on your own machine: a Docker image (amd64 and arm64), and
an install script for a plain Ubuntu VM. Both run the same programs as a firewall we host:

- **cc-proxy**: the proxy agents send their traffic through. It reads every request and applies the
  rules.
- **the firewall agent** (`mitm-agent`): holds the encrypted stores (channels, model keys, rules,
  logins, connectors), writes the proxy's rules and serves the firewall's pages.
- **OpenConnector**: makes the calls to connected apps. It listens on loopback only; agents reach it
  through the firewall agent's gate.
- **dnsmasq**: DNS for the agents (and, on a VM, chrony for their time). See "DNS and time".

Plan: [`docs/plans/standalone-firewall.md`](../docs/plans/standalone-firewall.md) §10 step 5.

The firewall agent runs in standalone mode (`MITM_MODE=standalone`,
[`docs/standalone/standalone-mode.md`](../docs/standalone/standalone-mode.md)): no ControlClaw console,
its own control plane (`cc-local`) in a local database, its pages opened with links it signs.

## The panel

The firewall serves its own panel on port 8800, on loopback (in Docker, published on the host's
loopback): open `http://localhost:8800` on the machine, or through an SSH tunnel
(`ssh -L 8800:127.0.0.1:8800 <server>`). At first start the firewall logs a one-time setup token
(`[cc-local] no admin yet …`; `journalctl -u controlclaw-mitm-agent`, or `docker compose logs
firewall`): the panel asks for it, then for the admin password. See
[`docs/standalone/panel.md`](../docs/standalone/panel.md). The rules and agents can also be set
through the API, as below.

## Rules and agents

Both are in the firewall's local database (`/opt/controlclaw/state/local.db`), and the proxy has
them on the next sync, within a minute. Set them with `PUT /api/egress-rules` and `PUT /api/agents`
([`standalone-mode.md`](../docs/standalone/standalone-mode.md) has the API and how to sign in):

- **Rules**: what agents may reach. Rules apply lower `priority` first, and a request no rule matches
  is allowed, so keep a `*` block rule last:

  ```json
  {"rules": [
    {"id": "1", "name": "Example", "match_domain": "example.com", "effect": "allow", "priority": 10},
    {"id": "2", "name": "Everything else", "match_domain": "*", "effect": "block", "priority": 100000}
  ]}
  ```

- **Agents**: the ones the proxy knows by their address, for the traffic log and per-agent rules
  (`vm_id`, `name`, `private_ip`; a `name` is lowercase letters, digits and `-`).

The block-everything rule a new firewall starts with comes from the local database, so a new
firewall is never an open proxy. An `egress-rules.json` or `rules.json` from an earlier install is
left where it is and not read: set those rules again through the API.

A firewall that has a ControlClaw console as its control plane runs with `MITM_MODE=saas`. When the
console's URLs (`STORE_URL`, `FIREWALL_URL`, …) are set and `MITM_MODE` is not, the container switches
to it and says so, and `install.sh` writes it into `/etc/controlclaw/firewall.env`.

## Opening a page

The firewall's Logs and Logins pages open with a link the firewall signs. It works once, within 60
seconds, and enrolls the browser that opens it:

```bash
docker exec -u controlclaw <container> mitm-agent open logins   # Docker
sudo -u controlclaw mitm-agent open logins                        # VM
```

The link is `https://<name>/__cc/local/open#…`, where `<name>` is the name your browser reaches the
firewall's pages (port 8790) at, on 443: `CC_HOSTNAME` in Docker, `--hostname` on a VM. It must be a
name with a dot and no port (`fw.example.com`, not `localhost` or `name:8443`). It is kept until you set
another one. Put HTTPS in front of
8790 with Caddy, Tailscale Serve or an SSH tunnel; for example, Caddy on the same machine:

```
fw.example.com {
  reverse_proxy 127.0.0.1:8790
}
```

## Ports

| Port | What | Who reaches it |
| --- | --- | --- |
| 8080 | the proxy (HTTP `CONNECT`) | your agents only |
| 3100 | the firewall agent, on loopback in standalone mode (`MITM_AGENT_LISTEN`) | nobody |
| 8790 | the firewall's pages and inbound webhooks | you, through a reverse proxy or an SSH tunnel |
| 3900 | the app gate (connectors) | your agents, when `CONNECTOR_GATE_BIND` is set |
| 3940 | the tools gate (MCP servers) | your agents, when `CONNECTOR_GATE_BIND` is set |
| 3910 | OpenConnector | loopback only, never published |
| 53 udp/tcp | DNS for the agents | your agents only |
| 123 udp | NTP for the agents (VM only) | your agents only |
| 8801 | pairing (`POST /pair`): answers only with a waiting one-time code | your agents' machines, while they pair |
| 8800 | the local panel and its API (`LOCAL_PANEL_BIND`) | you, on loopback or through an SSH tunnel |

Never open 8080 or 53 to the internet: anyone who reaches them can use your firewall as their proxy
or their resolver.

`CONNECTOR_GATE_BIND` is the firewall's address as your agents reach it (the gates listen on it and
the agents are told it). Unset, integrations stay off.

## DNS and time

Agents captured with `controlclaw connect --mode host` or `--mode docker` send their DNS to the
firewall (`--dns`). dnsmasq answers them with the same settings as a firewall we host: it asks
1.1.1.1, 8.8.8.8 and the machine's own resolver, and keeps 1000 names in its cache. It does not read
the machine's `/etc/hosts` (on a VM, systemd-resolved still answers the machine's own name).

- It answers every name. It does not filter: the proxy does, when the agent connects.
- It logs no queries, only its start, the servers it asks and errors (`journalctl -u controlclaw-dns`
  on a VM, `docker logs` in Docker). The names agents reach are in the proxy's traffic log.
- On a VM it listens on the proxy's address when that is a private one (10/8, 172.16/12,
  192.168/16, 100.64/10). With a public address or `0.0.0.0`, it listens on 127.0.0.1 only: a
  resolver on a public address answers the whole internet.
- In Docker it is published with the proxy on `CC_LISTEN`. With a `CC_LISTEN` that is neither loopback
  nor private, the container starts without DNS and says so, unless you set `CC_DNS_PUBLIC=1`
  because only your agents can reach that address.
- On a VM, chrony keeps the machine's clock and answers NTP on the same private address, from private
  addresses only. Without a private address it serves nobody. Installing it replaces
  systemd-timesyncd, as on a firewall we host. If another time server runs (ntpsec, ntp, openntpd),
  chrony is not installed and the agents get no NTP from the firewall; the script says so.
- The image has no NTP: a container uses the host's clock.

## The CA

The proxy reads HTTPS by signing a certificate for each site with its own CA. The CA is made at first
start and kept: `/opt/controlclaw/mitm/ca/ca-cert.pem` is the public half your agents must trust. The
private key never leaves the firewall. Removing the state makes a new CA, and every agent must then
trust the new one.

## Docker

Build both images (needs Docker with buildx; on an amd64 machine, run
`docker run --privileged --rm tonistiigi/binfmt --install arm64` once for the arm64 image):

```bash
standalone/docker/build.sh
```

This builds the binaries in the pinned build image (`rust/scripts/build-box.sh --docker`, both
architectures), then loads `controlclaw-firewall:dev-amd64` and `-arm64` and writes a two-platform
OCI archive to `rust/dist/docker/`.

Run it:

```bash
docker compose -f standalone/docker/compose.yaml up -d
docker compose -f standalone/docker/compose.yaml cp firewall:/opt/controlclaw/mitm/ca/ca-cert.pem .
```

- **State** is the volume on `/opt/controlclaw`: the CA, the box keys, the encrypted stores, the
  traffic log and OpenConnector's data. Back it up; losing it loses the CA and every stored secret.
- **`/run/mitm/config`** must be a tmpfs (`compose.yaml` has it): the decrypted secrets the proxy needs
  are kept in memory only. The container says so in its log when it is not.
- **Settings** are environment variables (`docker run -e`, or `environment:` in compose). The defaults
  are in [`lib/`](lib/); what you set wins.
- The entrypoint runs as root, sets up the volume, then starts each program as its own user: cc-proxy
  and the firewall agent as uid 10001, OpenConnector as uid 10003. The connector's keys file is root's;
  only the connector and the firewall agent get the keys. Do not set `--user`. When one program stops,
  the container stops, and the restart policy starts it again.

- **`CC_HOSTNAME`** is the name in the page links (see above).
- **Ports**: the proxy (8080) and DNS (53) are published on `CC_LISTEN`, the host's loopback by
  default, and the pages (8790) and the panel (8800) always on loopback. Agents need 8080 and 53 (and 3900, 3940) on an
  address they reach; allow only your agents there.
  - OpenClaw in Docker on the same machine: `CC_LISTEN=172.17.0.1 docker compose -f
    standalone/docker/compose.yaml up -d`, then `controlclaw connect --mode docker --proxy
    172.17.0.1:8080 --dns 172.17.0.1`. The capture's gate container reaches the firewall at the
    `docker0` address.
  - The gates (3900 app connections, 3940 MCP servers) are not published: they know an agent by
    the source address alone, and through a published port every caller on this machine arrives
    from the network's gateway. Agents in this setup have no MCP servers or app connections yet.
  - The firewall has a fixed address on its own network (`172.31.249.2` on `172.31.249.0/24`): a
    paired agent's vm-agent takes calls from that address only. A firewall run with a plain
    `docker run` on Docker's default bridge can get another address when it is recreated; then run
    `controlclaw connect` again on the agent's machine.
  - Agents on other machines: an address of yours on their network.
  - Docker's published ports go around a host firewall such as ufw: Docker writes its own rules. Only
    an address that only your agents reach keeps the others out.
  - Port 53 on that address must be free on the host, or the container does not start. If a
    resolver of yours has it, set `CC_DNS_PORT` to another port so the rest still runs. The capture
    modes send DNS to port 53 only, so for them use an address where 53 is free.

## Ubuntu VM

```bash
sudo standalone/install/install.sh --from rust/dist/aarch64-unknown-linux-musl   # a local build
sudo standalone/install/install.sh --version 0.2.0                               # a release
```

It checks the binaries against their `SHA256SUMS` (for a release, pass `--sums-sha256 <hash>` from a
place you trust; without it the check only shows the download is whole), installs them in
`/opt/controlclaw/rust/<version>/`,
installs `openssl` and Docker (for OpenConnector) when missing, makes the CA and the connector's keys
once, and starts these units:

- `controlclaw-mitmproxy`: the proxy.
- `controlclaw-connector`: OpenConnector, the image the Ansible role pins, on loopback.
- `controlclaw-dns`: dnsmasq for the agents (the `dnsmasq-base` package, without Ubuntu's own dnsmasq
  service). chrony is the distribution's own service.
- `controlclaw-mitm-agent`: the firewall agent, in standalone mode.
- `run-mitm-config.mount`: the tmpfs for the proxy's secrets.

Your own settings go in `/etc/controlclaw/firewall.env` (`KEY=value`, read by the proxy and the
agent; with your own `ORG_ID`, set `MITM_TENANT` to the same value for the traffic log). Running the script again updates the binaries and keeps the state. `--uninstall` removes the
units and binaries; `--uninstall --purge` also removes the state.

The proxy listens on the VM's private address when it has one, else on 127.0.0.1. Give
`--listen <address>` for another one: an address your agents reach, and nobody else. The script does not
set up a firewall on the VM; allow 8080, 53 and 123 (and 3900, 3940) only from your agents. DNS and NTP listen on the same address as the proxy when it is private (see "DNS and time").
`--hostname <name>` sets the name in the page links.

The script refuses a machine where `/opt/controlclaw` exists and it did not make it (a box our Ansible
role manages has the same unit names and folders), and `--uninstall` refuses one it did not install.

## WireGuard for remote agents

`install.sh --wireguard` (and `--wg-endpoint host[:port]` when the address agents reach is not this
machine's own) adds `cc-wg0` for agents on other machines: open UDP 51820 to them. In Docker, set
`CC_WIREGUARD=1` and `WG_ENDPOINT=host:51820`, add `cap_add: [NET_ADMIN]` and publish `51820/udp`. On
the agent's machine: `controlclaw connect --mode remote --firewall http://<this firewall>:8801`. See
[`docs/standalone/standalone-mode.md`](../docs/standalone/standalone-mode.md#wireguard-for-remote-agents).

## Publishing a port of a container behind the firewall

`CC_FORWARD` is a list of `<port>=<IPv4>:<port>` (comma-separated): the firewall relays each port to
that address (socat, as `controlclaw`). `controlclaw up --local` uses it for OpenClaw's gateway, which
is only on an internal network that Docker publishes nothing from.

## Not here yet

- The panel's pages for security rules, channels, integrations and website logins (they come as the
  firewall's API has them).
- NTP in the Docker image (it uses the host's clock).
- A published image and releases with arm binaries (plan step 15).
