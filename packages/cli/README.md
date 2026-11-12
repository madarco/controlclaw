# controlclaw

The `controlclaw` CLI puts OpenClaw behind a ControlClaw firewall. It installs the firewall, installs
OpenClaw, and connects the two. After `connect`, OpenClaw's traffic goes through the firewall, and the
vm-agent lets the firewall manage OpenClaw's models and channels. The firewall runs in Docker on Linux
and on macOS. `connect` needs Linux with systemd: the vm-agent is built for Linux only.

```bash
npx controlclaw up      # a menu: pick one of the ways below
```

Docker mode needs a user in the `docker` group (which can do what root does), or sudo. To add
yourself: `sudo usermod -aG docker $USER`, then log in again. Host and remote mode need sudo.

The three main ways:

| | Command | What it does |
| --- | --- | --- |
| A new OpenClaw and its firewall on one machine | `up --all` | Runs the firewall and OpenClaw as two containers. OpenClaw's only way out is the firewall. This is the strongest. |
| The OpenClaw you run, with its firewall next to it | `up --here` | Runs the firewall in a container on OpenClaw's machine, and connects OpenClaw to it with no code to type. |
| One firewall for OpenClaw on other machines | `install --listen <ip>` on the firewall, `connect --firewall <url>` on each OpenClaw machine | Runs the firewall on its own machine. Each OpenClaw connects with a one-time code. |

`up` only runs the commands below, in order. You can run each one on its own.

After a successful `up` at a terminal, it asks once whether you want to star the project on GitHub.
Yes stars it with `gh` when `gh` is signed in, and otherwise prints the link. It never asks without a
terminal or with `CI` set, and asks on at most two runs. The answer is kept in
`~/.local/state/controlclaw/star-prompt.json` (under sudo, in your own home).

## Commands

| Command | What it does |
| --- | --- |
| `up [--all \| --here]` | Shows a menu of the ways to set it up. `--all` and `--here` skip the menu. `up --local` is `up --all`. |
| `install [--docker \| --host] [--listen <ip>]` | Runs the firewall on this machine, as a container (the default) or as `install.sh`'s systemd units. Opens the panel. With `--listen`, it also prints a pairing code for other machines. |
| `openclaw install [--docker \| --host] [--firewall <url>]` | Installs a new OpenClaw on this machine, then connects it to `--firewall` or to the firewall `install` runs here. |
| `connect [--mode ...] [--firewall <url>] [--capture-only]` | Puts this machine's OpenClaw behind a firewall: installs the vm-agent, the firewall's CA and the capture for the mode. Without `--firewall`, it pairs with the firewall `install` runs here, with no code. |
| `open` | Opens the panel of the firewall on this machine. Until there is an admin, the link carries the setup token. With no desktop, it prints the link and the SSH tunnel to it. |
| `status [--json]` | Checks the firewall installed here, the capture, the vm-agent, and the firewall's proxy and DNS. Exits 1 if one of them is down. |
| `disconnect [--restore-config]` | Undoes everything `connect` did. `--restore-config` also puts back OpenClaw's config as it was before `connect`. |
| `uninstall [--purge]` | Runs `disconnect`, then removes the firewall installed here. Its data (rules, the panel's password, the CA) goes only with `--purge`. |
| `doctor [--json]` | Shows the OS, root access, nftables, Docker, redsocks, DNS, Chrome, WireGuard and the vm-agent, and OpenClaw's CLI, version, config and how it runs. Says which modes this machine can use and how much each one protects. |

Host and remote mode, `install --host` and `openclaw install --host` need root (sudo). Docker mode
needs root or a member of the `docker` group. Proxy mode needs neither.

Other ways to do each step:

| Step | The CLI | Otherwise |
| --- | --- | --- |
| The firewall | `controlclaw install` | `standalone/docker/compose.yaml` with `docker compose up -d`, or `install.sh` from the release (`install --host` runs it for you). See [`standalone/README.md`](../../standalone/README.md). |
| OpenClaw | `controlclaw openclaw install` | OpenClaw's own installer or its own `docker-compose.yml`, then `controlclaw connect`. Ansible comes later, because the role needs the control plane. |
| The connection | `controlclaw connect` | The OpenClaw skill [`controlclaw-connect`](../skills/controlclaw-connect/SKILL.md), which asks you, then runs `connect` for you. |

Options for `connect`:

| Option | Default | What it is |
| --- | --- | --- |
| `--mode` | `auto` | `auto` (docker for an OpenClaw in a container, else host), `docker`, `host`, `proxy` or `remote`. With the firewall installed here, only `auto`, `docker` or `host`. |
| `--firewall <url>` | the firewall installed here | The firewall's pairing address, such as `http://fw.example.com:8801`. Its host is also the last default for `--proxy` and `--dns`. Without it, `connect` pairs with the firewall `install` runs on this machine, with no code. |
| `--capture-only` | | The capture alone, with no vm-agent. The panel then can't set OpenClaw's models or bots, or stop it. |
| (asked) | | The one-time code from the firewall (`mitm-agent pair-code`), typed when `connect` asks. It brings the firewall's CA and key, and the agent's id. |
| `--code -` / `--code-file <file>` | | Reads the code from stdin, or from a file (keep it 0600). `--code <code>` is refused, because every user of the machine can read a command line. |
| `--name <name>` | this machine's hostname (`openclaw` with the firewall installed here) | The agent's name on the firewall, when the code has none (`pair-code --name` wins). |
| `--ca <file>` | | Without a code: the firewall's CA certificate (PEM). The firewall re-signs HTTPS with it. |
| `--firewall-key <pem>` | none | Without a code: the firewall's public key, as a file or the PEM itself. Without it, the vm-agent answers nothing. |
| `--proxy <host:port>` | what pairing says, else the firewall's host, port 8080 | The firewall's proxy. |
| `--dns <ip>` | what pairing says, else the firewall's host | The firewall's DNS server (host and docker modes). |
| `--user <name>` | found | The user OpenClaw runs as. By default the CLI uses the owner of the running gateway, or else the one user with `~/.openclaw/openclaw.json`. |
| `--vm-agent <path>` | `$CC_VM_AGENT`, then `/usr/local/bin/controlclaw-vm-agent`, then PATH, then this release's download | The vm-agent binary. |

## Pairing

On the firewall, as its user, make a code for one machine:

```bash
sudo -u controlclaw mitm-agent pair-code --name laptop      # or: docker compose exec -u controlclaw firewall mitm-agent pair-code
```

It prints a code such as `4F7K-92QD-XM3P`. It works once, within 10 minutes (`--ttl` up to 60).
At most 20 codes wait at a time. The admin API makes them too (`POST /api/pairing/codes`).

Only the admin decides these, on the code:
- `--address <ip>`: the address the proxy will see the machine at, when it is not the one pairing
  comes from (a NAT, a container on the firewall's machine). Without it, the agent's address is the
  one its request comes from, and that must be the address the machine says it has.
- `--replace`: the machine may take the place of an agent already at its address. Without it, the
  firewall refuses pairing at an address that has an agent.

`connect` first checks that the machine can use the mode, so it never spends a code on a machine
that can't. Then it pairs:
- it makes the vm-agent's key pair;
- it sends the public half to the firewall's `/pair` (port 8801);
- the firewall records the agent (its id, name, key, and the address the proxy will see it at);
- the firewall answers with its own public key, its CA, the agent's id and the proxy's and DNS
  addresses.

`connect` writes the key and the id into the vm-agent's config, and installs the CA. It prints the
CA's SHA-256, which the firewall's log shows at start, so you can compare them. The proxy knows the
agent at its next sync, within a minute.

The firewall calls the vm-agent to set a bot or a model, or for the emergency stop. Pairing tells the
firewall where to call (`agent_listen`), and the vm-agent listens there for the firewall's address
alone (`allow_from`; it closes any other connection). The calls are plain HTTP with the firewall's
signed tokens, the same tokens the SaaS sends over HTTPS.

| Mode | The vm-agent listens on | Who may connect |
| --- | --- | --- |
| host, proxy, docker, the firewall in a container on this machine (behind one of its Docker bridges, or published on a bridge's address such as `172.17.0.1`) | this machine's address on that bridge, port 3102 | the address the firewall calls from (pairing's `calls_from`: its container's) |
| host, proxy, the firewall installed on this machine itself (`install.sh`) | loopback only: the vm-agent would listen on the firewall's own address, which pairing refuses | nobody |
| host, proxy, docker, the firewall elsewhere | loopback only: the firewall does not call it (plain HTTP across a network) | nobody |
| remote | this machine's tunnel address, port 3100 | the firewall's tunnel address |
| `up --all`, `up --here`, `connect` to the firewall `install` runs here | `172.31.252.1:3102`, this machine on the firewall's `outside` network | the firewall's container (`172.31.252.2`) |

The vm-agent's port is 3102. Port 3100 belongs to the firewall agent and 3101 to its AI judge, and
with `up` the firewall shares the machine. Remote mode keeps 3100 on the tunnel address, where the
firewall calls it. A machine connected before keeps the `listen` its config has (port 3100) until it
connects again. The firewall has that address on record, so nothing changes for it.

Things to know about the firewall's calls:
- With the firewall on another machine, use `--mode remote` for bots, models and the emergency stop.
  The other modes capture traffic, but there the firewall can't reach the vm-agent. `connect` says
  so.
- Agents paired before this release have no address for the firewall's calls. Run `connect` again.
- `allow_from` is the firewall container's address at pairing. The Docker setup in
  `standalone/docker/compose.yaml` gives the firewall a fixed one (`172.31.249.2`). A firewall
  started with a plain `docker run` on Docker's default bridge can get another address when it is
  recreated. Run `connect` again then.
- MCP servers and app connections go to the firewall's gates directly (3940 and 3900, the
  firewall's default ports). Host and remote capture let OpenClaw's user reach them on the proxy's
  address. Docker capture relays them in its gate container, to a firewall whose gates are on an
  address it reaches (not `standalone/docker/compose.yaml`'s, which does not publish them). They don't
  work in proxy mode, where everything goes through the proxy, which never connects to the firewall
  itself. App connections don't work yet for an OpenClaw in a container.
- The emergency stop can't start again an OpenClaw that was started by hand (not by systemd, Docker
  or pm2). Start it yourself after the release.
- `allow_from` is the firewall's address as `connect` dialled it. When the firewall reaches this
  machine from another address (a NAT, a port forward, a second network), the vm-agent closes every
  call and logs `closed a connection from <ip>`. Set `firewall.allow_from` in the config by hand.
- OpenClaw can still ask the proxy for the vm-agent's address. The request then arrives from the
  firewall's address. An egress rule decides, as for any address, and the vm-agent still wants the
  firewall's signed token.

How the code is safe on plain HTTP:
- The code is never sent. The request carries an HMAC made with it. The firewall's answer carries an
  HMAC made with it too, and the answer must repeat a random value from the request.
  `connect` takes the firewall's key and CA only from such an answer. Someone in the middle sees two
  HMACs, and 60 bits cannot be tried offline within the code's lifetime.
- Guessing online is limited to ten wrong codes a minute from one address; after that the endpoint
  answers 429 for the rest of the minute. There is no limit over all addresses, because anyone could
  use such a limit to block every pairing. Even a million guesses a minute for 10 minutes find a
  60-bit code with odds of about 1 in 10^11.
- Once a code has matched, any refusal spends it (make a new one) and counts as a wrong try, so a
  refusal never tells a guesser that a code was right.
- The firewall keeps the plain code until it is used or expires, in its database, which only its
  user can read.
- The request says the machine's own address toward the firewall, under the HMAC. A request that
  arrives from another address is refused: someone who copied it on the way cannot pair from their
  own machine. Behind a NAT or a reverse proxy the two differ, so the admin names the address on
  the code (`--address`). The CLI pairs over the IPv4 address it measured its own address toward
  (for `http://`), so the two match.
- The agent cannot choose its address, and cannot take another agent's place unless the code says
  `--replace`. In host mode OpenClaw still has the internet until the capture is in. OpenClaw on
  that machine could read a code from a command line and pair first. It would get the same address
  and nothing more, and the real `connect` would then fail. That is why `connect` never takes the
  code from the command line.
- Two machines behind one NAT look like one to the proxy. Give each its own address the proxy sees
  (WireGuard remote mode does that).
- The address must be one the proxy can see an agent at: not loopback, unspecified, multicast,
  broadcast or the firewall's own.
- As root, `connect` writes nothing into a folder a user owns (OpenClaw's home: the vm-agent's
  keys, the systemd drop-in) and follows no link a user owns: those writes, and their undo, run as
  that user. A root folder on the way that the group or everyone may write to (a shared project
  folder) stops `connect`, which says which folder to `chmod go-w`.

Unpairing: pairing leaves a random secret in `connect.json` (the firewall keeps only its hash).
`disconnect`, and a `connect` that fails after pairing, send it to the firewall's `/unpair`, which
forgets the agent, so the machine can pair again later without `--replace`. When the firewall cannot
be reached, they say so; remove the agent there by hand (`PUT /api/agents`).

## Modes

| Mode | How | Protection |
| --- | --- | --- |
| `docker` | OpenClaw's container moves to a network with no way out except the firewall. | Strong: the container cannot reach the network without the firewall. |
| `host` | nftables catch every packet from OpenClaw's user. | Limited: anyone with root or sudo on the machine can remove the rules. |
| `proxy` | OpenClaw's own proxy setting. | Lets you see OpenClaw's own requests and block them. Shell commands and other programs go around it. |
| `remote` | WireGuard to the firewall, then host mode's rules through the tunnel. | Like host mode on the machine (root or sudo can remove the rules), from any network, with the tunnel address as its identity. |

### docker (needs Docker 28 and Compose 2.24.4 or newer; root, or a user in the docker group)

For an OpenClaw started with Docker Compose, for example OpenClaw's own `docker-compose.yml`.
`connect` stops in these cases:
- other services of that Compose project run with the gateway: the gateway leaves its network, so
  they would lose it;
- the gateway could get out on its own:
  - it mounts a container runtime's socket (`docker.sock`, containerd, podman) or a folder that holds
    one (`/`, `/run`, `/var`, a user's `/run/user/<uid>` for rootless Docker or podman);
  - it is `privileged`;
  - it has `NET_ADMIN`, `NET_RAW` or `SYS_ADMIN`;
  - it uses the host's network.

  The error says which; remove that from its compose file first.

- It writes an override, `/etc/controlclaw/docker/compose.controlclaw.yml`, and runs
  `docker compose ... up -d` for the gateway service only. Your compose files are not changed.
- The gateway container goes onto a new network, `<project>_controlclaw`, with `internal: true`.
  It has no route out. Its bridge gives this machine no address (`gateway_mode_ipv4: isolated`,
  Docker 28). Without that, an internal network still lets its containers reach every service of the
  host that listens on `0.0.0.0` (sshd, a resolver, a dev server). `status` checks it.
- A small `controlclaw-gate` container (socat) sits on that network and on the normal one. It sends
  port 8080 to the firewall's proxy and port 53 to the firewall's DNS. It also publishes the ports
  the gateway published before, such as the Control UI on 18789. Docker publishes no ports for a
  container that is only on an internal network, so the gate has to.
- The gateway gets `OPENCLAW_PROXY_URL`, `HTTP(S)_PROXY` and `NODE_USE_ENV_PROXY=1`. The CA is
  added in two ways:
  - `NODE_EXTRA_CA_CERTS`;
  - a CA bundle mounted over `/etc/ssl/certs/ca-certificates.crt`: the image's own bundle plus the
    firewall's CA.
- The firewall's gates (3900 app connections, 3940 MCP servers) are on the gateway's own
  `127.0.0.1`: OpenClaw's proxy setting sends everything but loopback to the proxy, which refuses
  the firewall's own address. A small relay (`gate-relay.mjs`, mounted read-only) starts in the
  gateway's container before its own entrypoint and command, which the override repeats as they
  were at `connect`. If you change them in your compose file later, run `connect` again.
- Anything that ignores the proxy (a direct IP, another DNS server, UDP) has nowhere to go.
- After a reboot, Docker brings both containers back the same way.
- `docker compose up -d` in the project's folder (an OpenClaw update, say) keeps the capture:
  `connect` adds `COMPOSE_FILE=<your files>:<the override>` to the project's `.env`, and
  `disconnect` takes it out.
  - If your `.env` already sets `COMPOSE_FILE` or `COMPOSE_PATH_SEPARATOR`, it is left alone and
    `connect` tells you to add the override yourself.
  - Run with `-f` and without the override, the gateway goes back on its open network. `status`
    shows it.

If the firewall runs on the same machine, it must listen where containers can reach it, such as
the `docker0` address (`172.17.0.1`), and `--proxy` and `--dns` must name that address. `connect`
refuses `127.0.0.1`: inside the gate it means the gate itself.

The network uses `172.31.250.0/24`. If another Docker network already uses it, `connect` stops.

### host (needs root and systemd)

For an OpenClaw installed on the machine, for example with the official installer. It runs as a
systemd user unit.

- `/etc/controlclaw/capture/capture.nft` holds the rules for OpenClaw's uid only:
  - TCP goes to redsocks, which hands it to the firewall's proxy;
  - DNS (port 53, UDP and TCP) goes to the firewall, whatever server was asked, except
    systemd-resolved's own stub (127.0.0.53), which itself asks only the firewall (below). A query
    from 127.x sent on to another machine would be dropped as martian;
  - IPv6, ICMP and other UDP are refused;
  - on the machine itself (127.0.0.0/8, ::1) only these TCP ports are allowed:
    - redsocks and the vm-agent (3102);
    - OpenClaw's own, derived from the gateway port as OpenClaw 2026.10 does: the gateway, browser
      control (+2), the extension relays (+3 to +10) and the default browser profile's CDP (+11),
      so 18789 to 18800 by default;
    - the CDP port each other browser profile has in OpenClaw's config. If that config is not
      plain JSON (JSON5), its profiles cannot be read, so the whole range OpenClaw uses (to +110)
      stays open.

    Anything else listening there is refused, so that sshd with the user's keys, a local proxy or a
    resolver on `::1` cannot be a way out. A root program that listens on one of those ports would
    still be reachable. A browser profile made after `connect` gets a new CDP port, which is refused
    until you run `disconnect` and `connect` again.

    OpenClaw's Codex relay (the ChatGPT/Codex provider) listens on a random port and does not work in
    host mode. Use docker mode for it.
- `controlclaw-capture.service` loads the rules at boot, before the network is up. It does not wait
  for the firewall. If the firewall is down, OpenClaw cannot reach anything.
- `nftables.service` flushes the whole ruleset on start, restart, reload and stop. So ours loads
  after it at boot, and a drop-in (`nftables.service.d/controlclaw.conf`) has it load ours again
  after each of those. Anything else that flushes the ruleset (`nft flush ruleset`, `nft -f` of a file that
  flushes) removes it; `status` shows when the table is missing.
- `controlclaw-redsocks.service` runs redsocks under its own user. `apt-get install redsocks` runs
  if it is missing, and `disconnect` removes it again.
- The CA is added to the system store, to OpenClaw's service (a drop-in that sets
  `NODE_EXTRA_CA_CERTS`) and to Chrome's stores, if Chrome and `certutil` are installed. OpenClaw is
  restarted so it reads it.

resolved also gets `LLMNR=no` and `MulticastDNS=no`, and its user may not send to ports 5353 and
5355: otherwise a single-label or `.local` name would go onto the local network.

**The whole machine's DNS depends on the firewall.** Most programs look names up through
systemd-resolved, not port 53, so `connect` points resolved at the firewall
(`/etc/systemd/resolved.conf.d/controlclaw.conf`). It also allows resolved to ask only the firewall:
not a DNS server a network link got from DHCP, and not DNS over TLS. If the firewall stops, DNS stops for every
program on the machine, not only OpenClaw. `doctor` says so before you connect, and `status` shows
it when the firewall's DNS does not answer.

Host mode refuses to run in these cases:
- OpenClaw runs as root. The rules would then catch every root program. Run OpenClaw as its own user.
- OpenClaw's user is in the `docker` group (or `lxd`, `incus`, `libvirt`, `podman`). It could start a
  container whose traffic dockerd sends, not the user, so the rules would never see it. Remove the
  user from the group (`gpasswd -d <user> docker`), or use docker mode. If the user's groups cannot
  be read (`id -nG` fails), host mode refuses too.
- systemd-resolved runs but has no `systemd-resolve` user: its queries could not be limited to the
  firewall's DNS.

### remote (needs root, systemd, and a firewall with WireGuard)

For a machine that reaches the firewall over the internet: another cloud, a home server. The firewall
runs WireGuard (`install.sh --wireguard`). Pair with a code; `--ca` is refused here.

```bash
sudo controlclaw connect --mode remote --firewall http://fw.example.com:8801 --vm-agent ./vm-agent
```

- Before pairing, `connect` makes this machine's WireGuard key pair. Pairing sends the public half,
  and the firewall answers with a tunnel address (its identity at the proxy, such as `10.77.0.2`),
  its own WireGuard key and endpoint, and its tunnel address (`10.77.0.1`).
- `/etc/wireguard/cc-wg0.conf` and `cc-wg0.key` (root only), brought up by `wg-quick@cc-wg0` before
  anything else, and `connect` waits (up to about 45 seconds) for the firewall's first answer. When
  none comes (UDP to its endpoint blocked), it stops and undoes all of it. Only the
  firewall's tunnel address goes into the tunnel: the machine's other traffic keeps its routes.
  `wireguard-tools` is installed if missing, and removed by `disconnect`.
- Then the same capture as host mode, with the firewall at its tunnel address: redsocks to
  `10.77.0.1:8080`, DNS to `10.77.0.1`, resolved pointed there. Two more rules in the table:
  - after routing, nothing for the firewall's tunnel address leaves by another interface. With the
    tunnel down, OpenClaw's traffic, its DNS and resolved's queries go nowhere: they never leave in
    clear on the public interface;
  - the vm-agent listens on this machine's tunnel address, and only the tunnel reaches it (and
    there only the firewall's end, `allow_from`);
  - what goes into the tunnel leaves from this machine's tunnel address (DNS that OpenClaw sends to
    another server is DNATed into the tunnel, and the firewall takes only that address from it);
  - nothing forwarded goes into the tunnel: a container on this machine (which Docker masquerades)
    would otherwise reach the firewall as this agent.
  The rules judge only OpenClaw's user's packets; the kernel's own (WireGuard's UDP) are not refused.
- Behind a NAT it works as it is: over WireGuard the identity is the tunnel address, not the address
  pairing comes from. (A request copied on the way and replayed elsewhere would register a key whose
  private half only this machine has.)
- `status` shows the tunnel and its last handshake.
- `--proxy` and `--dns` are refused: they would send the capture outside the tunnel, in clear.
- A machine set up again from scratch (its `connect.json` lost) gets a new WireGuard key and a new
  tunnel address. The old peer stays on the firewall until the admin removes that agent (`PUT
  /api/agents`, or the panel): `disconnect` removes it only when it still has the record.
- The limits of host mode apply: OpenClaw's own user, not root, not in the docker group, no sudo.

### proxy (no root needed)

For any OpenClaw on the machine, also on a machine without root.

- It sets OpenClaw's managed proxy: `proxy.enabled`, `proxy.proxyUrl` (the firewall's proxy) and
  `proxy.loopbackMode: gateway-only`. `disconnect` removes the setting again.
- `connect` stops if OpenClaw already has a proxy setting, so that `disconnect` never loses one. It
  reads the setting from OpenClaw's config file, because `openclaw config get` hides the URL. If that
  file is not plain JSON (JSON5 with comments), `connect` stops too.
- `proxy.tls.caFile` is not used: it only verifies an `https://` proxy. To trust the firewall's CA,
  OpenClaw's service gets `NODE_EXTRA_CA_CERTS`.
- It is part of OpenClaw's config, so it stays after a reboot. When the proxy is down, OpenClaw's
  requests fail; they do not go out directly.
- `status` runs `openclaw proxy validate`.

## up

```bash
npx controlclaw up            # the menu
npx controlclaw up --all      # the firewall and a new OpenClaw here (install, openclaw install, connect)
npx controlclaw up --here     # the firewall next to the OpenClaw here (install, then connect)
```

The menu has five choices:

| Choice | What it runs |
| --- | --- |
| Firewall + new OpenClaw here | `up --all` |
| Protect the OpenClaw here | `up --here` |
| Firewall only | `install`, after asking for the address other machines reach this one at (empty: this machine only) |
| New OpenClaw only | `openclaw install --firewall`, after asking for the firewall's pairing address |
| Connect this OpenClaw | `connect --firewall`, after asking for the firewall's pairing address |

Choose with the arrow keys. When stdin is not a terminal (`curl … | sh`), the menu asks for a number on
the terminal instead. With no terminal at all, it stops and asks you to pass `--all` or `--here`.

`up --local` is the older name of `up --all`
([details below](#up---all-up---local-the-firewall-and-openclaw-on-one-machine)).

## install

```bash
npx controlclaw install                              # this machine only
npx controlclaw install --listen 10.0.1.5            # also for OpenClaw on other machines of your network
sudo npx controlclaw install --host                  # install.sh's systemd units instead: they need root
```

- `--docker` (the default) runs the image of this CLI's release,
  `ghcr.io/madarco/controlclaw-firewall:<version>`, and pulls it when missing (`--firewall-image`
  picks another). It makes a Compose project, `controlclaw-firewall`, in `/etc/controlclaw/firewall/`
  (`~/.config/controlclaw/firewall/` without sudo). The container gets two networks with fixed
  addresses, so `allow_from` stays right when the container is recreated:
  - `outside` (`172.31.252.0/24`), with the firewall at `.2` and this machine at `.1`;
  - the internal `agents` (`172.31.251.0/24`), with the firewall at `.2` and no address for this
    machine.

  Its panel (8800), pairing (8801) and pages (8790) are published on this machine's loopback only.
  `install` stops when something already listens there, or when Docker is rootless. Rootless Docker's
  networks are in a namespace of their own, where this machine has no address for the vm-agent.
- `--listen <ip>` also publishes the proxy (8080), DNS (53), pairing (8801) and the gates (3900, 3940)
  on that address, and pairing tells agents to use it. It must be a private address, because on a
  public one the proxy and DNS would answer the whole internet. Allow only your agents there (with
  `ufw` or your cloud's firewall). Docker's published ports go around `ufw`.
- `--host` downloads this release's `controlclaw-install-<version>.tar.gz`, checks it against the
  signed SHA256SUMS, and runs its `install.sh --version <version> [--listen <ip>]`. It needs root.
  `connect` with no `--firewall` can't pair with this firewall by itself. Make a code in its panel.
- At the end, `install` runs `open`, then says how to connect OpenClaw. On this machine, run `connect`,
  which pairs by itself (container firewall only). On another machine, run `connect --firewall
  http://<listen>:8801` with the pairing code `install` prints, which works once, within 10 minutes.
- Run again, `install` starts the firewall if it is not running and opens the panel.
- `uninstall` removes the firewall. Its data (the volume, or `/opt/controlclaw` for `--host`) goes only
  with `--purge`.

## openclaw install

```bash
npx controlclaw openclaw install                                     # in Docker, connected to the firewall here
npx controlclaw openclaw install --firewall http://10.0.1.5:8801     # asks for the code
sudo npx controlclaw openclaw install --host                         # installs Node and makes a user: needs root
```

- `--docker` (the default) makes a Compose project like OpenClaw's own `docker-compose.yml` (one
  service, `openclaw-gateway`) in `/opt/openclaw` (`~/openclaw` without sudo, `--dir` for another
  folder), with `ghcr.io/openclaw/openclaw:2026.10.9` (`--openclaw-image` for another). Its Control UI
  is published on this machine's loopback only. `openclaw install` prints its address with the gateway
  token.
- `--host` runs OpenClaw's own installer (`https://openclaw.ai/install.sh --no-onboard --no-prompt`) as
  root. The installer installs Node 24 and build tools, and puts `openclaw` on every user's PATH. Then
  `openclaw install` sets OpenClaw up as its own user (`openclaw`, or `--user`, made when missing, never
  root), with its gateway as that user's systemd service. Lingering is on, so the gateway runs without
  a login. Needs root.
- Then it connects the new OpenClaw:
  - with `--firewall`, to that firewall, asking for the code;
  - without it, to the firewall `install` runs here as a container, with no code;
  - with neither (no `--firewall`, and no container firewall here), it says what to run next.
- It stops when OpenClaw is already on the machine. Use `connect` then.
- There is no Ansible way yet, because the role needs the control plane.

## connect, to the firewall on this machine

```bash
npx controlclaw connect          # docker mode
sudo npx controlclaw connect     # host mode: nftables rules and a system service
```

Without `--firewall`, `connect` pairs with the firewall that `install` runs here as a container, with
no code to type. It makes a code inside the firewall's container, with the address the proxy will see
OpenClaw at (docker mode: `172.31.251.10`; host mode: this machine on `outside`, `172.31.252.1`).

- `--mode auto` (the default) picks **docker** for an OpenClaw in a container and **host** for one
  installed on the machine. It stops when there is no OpenClaw, or when the mode's checks fail (the
  same checks as with `--firewall`). Proxy and remote mode need `--firewall`.
- **docker:** like `--mode docker` with a firewall elsewhere, but OpenClaw's gateway joins the
  firewall's `agents` network instead of a network of its own with a gate container. The firewall's
  container is its proxy, its DNS and its only way out. The firewall's container also publishes the
  ports the gateway published (its Control UI), on the same host addresses (`CC_FORWARD`), so
  `connect` restarts the firewall once to take them. MCP servers and app connections don't work yet,
  as with docker mode against a firewall elsewhere.
- **host:** host mode, with the firewall's proxy, DNS and gates at `172.31.252.2`.
- The vm-agent listens on `172.31.252.1:3102`, for the firewall's container alone (`allow_from`).
- `status` adds a check for the firewall's container. In docker mode it checks the firewall from
  inside OpenClaw's container, because this machine is not on that network.
- Run again, `connect` checks what is there and never pairs twice. A `connect` that fails undoes
  itself (and unpairs), so the next one starts over.
- `disconnect` puts OpenClaw back and leaves the firewall running. `uninstall` removes both.

**Without sudo (docker mode).** A user who can use Docker (in the `docker` group) can run `up`,
`up --all`, `up --here` (OpenClaw in Docker), `install`, `openclaw install --docker`, `connect` in
docker mode, `open`, `status`, `disconnect`, `uninstall` and `doctor` without sudo. This saves a
password prompt, not a risk, because the `docker` group can do what root does. A machine set up with
sudo is run with sudo afterwards.

- The records, the override and the CA are in `~/.config/controlclaw/`. The vm-agent is in
  `~/.local/bin/` and runs as a systemd user service. `connect` turns on lingering (`loginctl
  enable-linger`) so the vm-agent keeps running after you log out and starts at boot. `disconnect`
  turns it off again if `connect` turned it on. If `connect` can't turn it on, it says so: run
  `sudo loginctl enable-linger <you>`.
- Docker mode stops before pairing when your Compose can't read the project's files (a root
  project's `.env` is 0600). Run it with sudo, or as the project's owner.
- `status` and `disconnect` find the record either way. With sudo, on a machine set up without it,
  they run as the user who set it up (`$SUDO_USER`), or say how to.
- Host mode needs root (nftables).

**`--capture-only`.** No vm-agent. OpenClaw's traffic goes through the firewall, but the panel can't
set OpenClaw's models, bots or MCP servers, or stop it. Nothing writes to OpenClaw's config.

## What connect changes, and what disconnect puts back

| Mode | connect changes | disconnect puts back |
| --- | --- | --- |
| docker | OpenClaw's gateway: an override file next to your compose files, named in the project's `.env` (`COMPOSE_FILE`); the gateway moved to the internal network; the CA bundle; the gate container (firewall elsewhere) or the firewall's port relays (firewall here) | the gateway on its own networks with its ports, the `.env` line removed, the override, bundle and gate removed |
| host | nftables rules for OpenClaw's user, redsocks, resolved pointed at the firewall, the CA in the system store, Chrome and a drop-in on OpenClaw's unit; OpenClaw restarted | all of them removed, resolved as it was, OpenClaw restarted |
| proxy | OpenClaw's `proxy` setting, the CA drop-in | the setting removed |
| remote | as host, plus the WireGuard tunnel | as host, the tunnel removed |
| every mode | the vm-agent (its binary, config and unit); what the panel sets through it goes into OpenClaw's config (a model, a bot, MCP servers, secrets) | the vm-agent removed. OpenClaw's config keeps what the panel set, unless `--restore-config` |

Before the vm-agent first writes to OpenClaw's config, `connect` keeps a copy of it (0600, in the
state folder: `/etc/controlclaw/openclaw.json.before-controlclaw`). `disconnect --restore-config` puts
the copy back (as the file's owner, never through a link) and restarts OpenClaw. `disconnect` alone
removes the copy and keeps what the panel set.

## open

`open` opens the panel of the firewall on this machine, which is always at `http://127.0.0.1:8800`.
Before there is an admin, the link carries the newest setup token in its fragment
(`http://127.0.0.1:8800/#setup=<token>`), never in the query or a log. The browser does not send the
fragment, and the panel fills the token in and removes it from the address bar. `open` reads the
token from the firewall's log: `docker compose logs` for `install`, `up --here` and `up --all`,
`journalctl` for `install.sh`, which needs sudo.

With a desktop (`$DISPLAY` or `$WAYLAND_DISPLAY`), it runs `xdg-open` as the user who ran the command,
not root (`$SUDO_USER` under sudo). The token never goes on a command line: `open` writes a short page
only that user can read, opens that, and removes it after a few seconds. With no desktop, it prints
the link and `ssh -L 8800:127.0.0.1:8800 <machine>`. `install`, `up --here` and `up --all` run it at
the end.

## up --all (up --local): the firewall and OpenClaw on one machine

```bash
npx controlclaw up --all
```

It runs `install`, `openclaw install --docker` and `connect`, the same code as the three commands,
then `open`:

- **The firewall:** the Compose project `controlclaw-firewall`, its files in
  `/etc/controlclaw/firewall` (`~/.config/controlclaw/firewall` without sudo). `--firewall-image`
  picks another image.
- **OpenClaw:** the Compose project `openclaw`, in `/opt/openclaw` (`~/openclaw` without sudo;
  `--dir` for another folder). `--openclaw-image` picks another image.
- **The connection:** docker mode. OpenClaw's container joins the firewall's internal `agents`
  network as its only network, so the firewall is its only way out. `--name` and `--vm-agent` work as
  for `connect`.

Run again, it checks what is there. After a stop half way, it goes on from there.

A machine set up by `up --local` or `up --all` of 0.10.0 or earlier (as root, two containers in one
Compose project, `controlclaw-local`, in `/opt/controlclaw-local`) keeps working.
`sudo npx controlclaw status`, `disconnect` and `uninstall` handle it. `up --all` on it only runs its
checks and says how to move: `sudo npx controlclaw uninstall`, then `npx controlclaw up --all`. The
new OpenClaw starts empty; the old one's data stays in its folder.

## What disconnect does

`connect` and `up` write each step to `/etc/controlclaw/connect.json` (`~/.config/controlclaw/` without
root). After a `connect` with sudo, run `disconnect` and `status` with sudo too; without sudo they
tell you so. `disconnect` undoes the steps in reverse:

- it puts back each file it changed, and removes the files and folders it created;
- it stops and removes the units;
- it restores OpenClaw's settings;
- it restarts OpenClaw last.

If `connect` fails halfway, it undoes itself the same way. A step that fails stays in `connect.json`
and the rest still run, so you can run `disconnect` again once you fix the cause. For a step that can
never work again (its file is gone), `disconnect --force` gives it up and lists what to check by
hand.

A file `connect` changed (a project's `.env`) gets its content, mode and owner back. If the vm-agent
binary was already at `/usr/local/bin/controlclaw-vm-agent`, `connect` uses it where it is and leaves
it there. Someone else's binary there is set aside as `.before-controlclaw` and put back. If such a
file is already there (from a connect whose record was lost), `connect` stops rather than overwrite
it.

## Gotchas

- **The CA needs a restart.** Node reads `NODE_EXTRA_CA_CERTS` only when it starts, so `connect`
  restarts OpenClaw. If OpenClaw runs with pm2 or as a plain process, add the variable to how you start
  it.
- **sudo.** If OpenClaw's user can use sudo, then in host mode OpenClaw, or its agent, can remove the
  rules. `doctor` warns about it.
- **The vm-agent runs as OpenClaw's user** in host and proxy mode. For Docker it runs as root, or as
  your own user when you ran `connect` or `up` without sudo. See
  [`rust/bins/vm-agent/UNMANAGED.md`](../../rust/bins/vm-agent/UNMANAGED.md).
- **The firewall must serve DNS** on port 53 for host and docker mode. Without it, `connect` still
  runs, but `status` shows the DNS check failing.
