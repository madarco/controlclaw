# The desktop app as a node

OpenClaw's gateway runs behind the firewall: in a container (`controlclaw up --all`) or on a machine
connected in remote mode (`controlclaw connect --mode remote`). Your own computer joins the gateway as
a **node**. The gateway can then run commands on it (`system.run`), use its browser and read its
files, each after you approve it. The work runs in the gateway; your computer only answers what the
gateway asks.

The macOS app is one kind of node (Remote over SSH, or Remote direct ws/wss). `openclaw node run` is
the headless kind, on macOS, Linux or Windows. Both speak the same protocol to the gateway. This page
was tested with OpenClaw 2026.10.9 and a headless node on Linux. Nobody has run the macOS app's own
screens yet (see [Not tested](#not-tested-the-macos-app-itself)).

## What you need

- The gateway's token:
  - `up --all` prints it (`OpenClaw: http://127.0.0.1:18789/#token=…`);
  - on a machine you connected, run `openclaw config get gateway.auth.token`.
- A way to approve the node on the gateway. Use either:
  - the Control UI (Settings → Devices);
  - the CLI on the gateway's machine (`openclaw devices list`, `openclaw devices approve <id>`,
    then `openclaw nodes pending`, `openclaw nodes approve <id>`).

  With `up --all`, run the CLI inside the container:
  `docker exec controlclaw-local-openclaw-1 node dist/index.js devices list`.

A new node needs **two approvals**: first the device, then the commands it offers (its "surface").
Until the second one, the node is connected but can do nothing. After that it reconnects by itself
after a restart on either side, with no new approval.

## `up --all`: the gateway in a container

The firewall container publishes the gateway's port on this machine's loopback only
(`127.0.0.1:18789`). OpenClaw itself is on an internal network with no other way in.

- **The Mac that runs `up --all`:** in the app, choose Remote, Direct, `ws://127.0.0.1:18789`, and
  the token. For a headless node:

  ```bash
  OPENCLAW_GATEWAY_TOKEN=<token> openclaw node run --host 127.0.0.1 --port 18789 --display-name "My Mac"
  ```

- **Another computer:** open an SSH tunnel to that machine's loopback, then do the same with the
  tunnel's local port. The app's Remote over SSH mode opens the tunnel itself.

  ```bash
  ssh -N -L 18790:127.0.0.1:18789 you@the-machine
  OPENCLAW_GATEWAY_TOKEN=<token> openclaw node run --host 127.0.0.1 --port 18790 --display-name "Laptop"
  ```

The gateway sees the node at the firewall's address (`172.31.251.2`), not at loopback. So it asks for
both approvals, as for any other remote device.

## Remote mode: the gateway on another machine

The gateway listens on that machine's loopback (`gateway.bind: loopback`, the default).

- **SSH tunnel** to the gateway's machine (the app's Remote over SSH, or `ssh -L` and `node run` as
  above).

  This path **does not go through the firewall**. The gateway sees the node at loopback and, by
  default, **approves its device and its first surface without asking**, `system.run` included
  (OpenClaw's "local auto-approve"). Anyone with an SSH login on that machine can join a node that
  way. Turn it off on the gateway, so each node asks:

  ```bash
  openclaw config set gateway.nodes.pairing.autoApproveLocal false
  ```

- **Direct (ws/wss) through the firewall.** This was tested by hand; the CLI does not set it up yet.
  1. Make the gateway also listen on its tunnel address:
     `openclaw config set gateway.bind custom`,
     `openclaw config set gateway.customBindHost <the machine's tunnel address, e.g. 10.77.0.2>`,
     then restart the gateway. It then listens on loopback and on that address. Remote mode's rules
     let only the tunnel reach the tunnel address, so only the firewall can reach it.
  2. Make the firewall relay a port to it: set `NODE_RELAY=0.0.0.0:18790=10.77.0.2:18789` in
     `/etc/controlclaw/firewall.env`. Add `NODE_RELAY_TLS=<cert.pem>,<key.pem>` for `wss://`. Then
     restart the firewall agent. Open that port only to the computers that join as nodes.
  3. Connect the node to the firewall, pinning the firewall's certificate:

     ```bash
     OPENCLAW_GATEWAY_TOKEN=<token> openclaw node run --host <firewall> --port 18790 \
       --tls --tls-fingerprint <sha256 of the relay's certificate>
     ```

     In the Mac app: Remote, Direct, `wss://<firewall>:18790`, and the same fingerprint in
     `gateway.remote.tlsFingerprint`.

  OpenClaw refuses plain `ws://` to a public address, and so does the relay. Beyond loopback, the
  relay starts only with `NODE_RELAY_TLS`, or with `NODE_RELAY_INSECURE=1` on a private network (the
  gateway token is in the node's first frame). The relay's own connection to the gateway is plain
  `ws://`, so the gateway must be at a private address, as the tunnel address is. The relay refuses a
  gateway on loopback (in any spelling, or a name that resolves there), because the gateway would
  then approve every node as local. The gateway sees the node at the firewall's tunnel address
  (`10.77.0.1`) and asks for both approvals.

`NODE_RELAY` is an experiment. The firewall only writes to its journal which node connected and what
the gateway asked it to run. It enforces nothing.

## The node's own traffic

What the node does (a shell command, a page its browser opens) goes out over **the node's own
network**, not through the firewall. Two settings on the node change part of that:

- `proxy.enabled` and `proxy.proxyUrl` (the firewall's proxy), with `NODE_EXTRA_CA_CERTS` set to the
  firewall's CA. The node process's own requests, its update check included, then go through the
  firewall, under the rules of the agent the firewall knows it as.

  The node's connection to the gateway goes through the proxy too, unless it is on loopback. So
  connect the node through an SSH tunnel (`--host 127.0.0.1`). The proxy refuses an IP address as a
  destination, and would replace a pinned certificate with its own.
- A command run with `system.run` gets `HTTP_PROXY`/`HTTPS_PROXY` in its environment. A program that
  ignores them (`curl --noproxy '*'`) goes out directly.
- The node's browser takes a proxy through `browser.extraArgs: ["--proxy-server=…"]`. OpenClaw then
  refuses every navigation unless `browser.ssrfPolicy.dangerouslyAllowPrivateNetwork` is on. Nobody
  has tried this yet.

## Not tested: the macOS app itself

There is no Mac in the test setup. These points come from OpenClaw's docs (`platforms/mac/remote.md`)
and still need a check on a Mac:

- the app's Remote over SSH and Remote direct settings, and its approval panel;
- the Keychain pin: the app pins a `wss://` certificate on first use only after macOS trusts it. A
  self-signed relay certificate needs `gateway.remote.tlsFingerprint` set by hand;
- the Mac-only commands (`system.notify`, `canvas.*`, `camera.*`, `screen.*`) through the relay.
