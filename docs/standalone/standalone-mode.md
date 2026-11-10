# Standalone mode

A standalone firewall runs with no ControlClaw console. Its own control plane, `cc-local`, is built
into the firewall agent and keeps its state in a SQLite file. The firewall opens its own pages with
links it signs itself, and keeps the console's modules off. The [panel](panel.md) uses the API on this
page.

## Turning it on

Set `MITM_MODE=standalone` in the firewall agent's environment (`mitm-agent`, the Rust build). The
default is `saas`, and an unknown value stops the agent at start.

In standalone mode:

- **No console.**
  - `FIREWALL_URL`, `STORE_URL`, `RULES_URL`, `IDENTITIES_URL`, `WEBHOOKS_URL`, `PERMISSION_URL`,
    `CA_URL`, `ACTIVITY_URL`, `MIGRATE_FROM_URL` and `CONTROLPLANE_MCP_URL` must each be unset, a
    `file:` path, or a `local:` endpoint.
  - A web address stops the agent, so a box set up for the console never starts half standalone.
  - There is no heartbeat, and `saas_public_key.pem` is not needed.
- **Names.** `ORG_ID` defaults to `local` and `BOX_ID` to `firewall`.
- **Its own control plane.** The agent answers the contract
  ([`control-plane-contract.md`](control-plane-contract.md)) in process. Unset, each endpoint
  variable points at it (`local:/api/vm-agent/<endpoint>`):

  | Variable | What the local control plane does |
  | --- | --- |
  | `RULES_URL` | The egress rules and AI settings in its database. |
  | `IDENTITIES_URL` | The agents in its database: the ones the proxy recognises by source address. |
  | `PERMISSION_URL` | Requests the proxy raises (`PENDING_PATH`, default `<PROXY_CONFIG_DIR>/pending.jsonl`) wait for an answer through the API. An approval becomes a grant for the proxy, as with the console. |
  | `ACTIVITY_URL` | The traffic log (`TRAFFIC_LOG_PATH`) is shipped into its database. Raw rows are kept 30 days, the hourly rollup 13 months. |
  | `CA_URL` | The CA the firewall publishes is kept for the agents. |

  - The database is `STATE_DIR/local.db` (default `/opt/controlclaw/state`).
  - A new database has no rule: every site is let through and logged. **Every other site: Block**
    (`PUT /api/egress/default`) is one rule, `block-all` (`*`, block, priority 100000), after every
    other; Allow removes it. A database from before November 2026 started with that rule and keeps
    it (one the admin changed since becomes an ordinary rule of theirs). The log says so at each
    start while it is the only rule. `PUT /api/egress-rules` replaces the whole list, so send it with
    that rule to keep every other site blocked.
  - The firewall adds rules of its own (`managed`, priority -5, before any of yours) for each model
    key it holds (its host, for every agent), and for each bot, AgentMail inbox and Gmail grant that
    has an agent (their hosts, for that agent), so they keep working when every other site is
    blocked. They are not rows: `/egress-rules` makes them from the keys and from the firewall's own
    lists (`channels.read`, `agentmail.read`, `google.read`, read at start, when a page shows them and
    after each change), and they go with them. The hosts are in
    `rust/crates/cc-contracts/managed-egress.json`. Because they come first, a rule of yours for one
    of those hosts (ask, block, AI review) is not reached: remove the key or the bot instead.
  - The proxy writes `managed` on each request such a rule let through. The AI log review skips
    those that carry the organization's own key or token, which the firewall put in (the model
    calls carry the agent's whole conversation; the bot's polling is the same request every few
    seconds). It still reads one sent with a key the firewall did not put in (someone else's bot or
    account on the same host), anything refused there, and your own rules for the same host.
  - The store stays a file (`file:<STATE_DIR>/store.json`): it is the console's backup and is not
    needed.
  - A variable set to a `file:` path still wins, as before the local control plane. For example,
    `RULES_URL=file:/etc/fw/rules.json` reads `{"rules": [...]}` or a bare list from that file on
    each sync. An empty list allows every host. The sync fails, with the reason in the log, when the
    rules file is missing, is not JSON or holds no list of rules (`{}`, `{"rules": null}`, a
    misspelled key). The proxy then keeps the last rules it had, and with none it refuses every
    request.
  - `STATE_DIR` moves only the database and the store. Each module's own store (`access.enc`,
    `channels.enc`, …) stays under `/opt/controlclaw/state` unless its own variable names another
    path.
- **Modules that stay off.** Phone and meetings run on ControlClaw's Twilio account and speech billing,
  so they are off. Team chat and Doctor (with its template checks) are off too. Included AI,
  backups, the brain (gbrain), templates, Tailscale, devices, support SSH and updates are the SaaS's,
  so they are off as well.
- **Modules that run.** With the local control plane as its control channel, a standalone firewall
  runs the content rules, the emergency stop, web search, the exit proxy (your own account with a
  proxy provider, not ControlClaw's relay) and the MCP servers (with `CONNECTOR_GATE_BIND` set); the
  panel's API sets them (`panel-api.md`). OAuth sign-ins come back to `LOCAL_PANEL_URL`, which
  Google takes only as `https://` or `http://localhost`: use an SSH tunnel to localhost, or set it
  to the panel's `https://` address. The tools
  gate (3940) serves the MCP servers and the logins tools; the ControlClaw MCP behind its `/mcp` is
  the SaaS's, so there it answers 404.
- **Recovery routes** (`RECOVERY_ROUTES`, the backup restore on port 3100 over TLS) default to off.
- **The proxy.** `cc-proxy` needs no change and no control plane: `MITM_CONTROL_PLANE_HOST` stays
  unset. It reads the files the agent writes in `PROXY_CONFIG_DIR` (`/run/mitm/config`), so its unit
  names them, as the Ansible role's does:

  ```ini
  Environment=MITM_TENANT=local
  Environment=MITM_CA_DIR=/opt/controlclaw/mitm/ca
  Environment=MITM_LOG_FILE=/var/log/controlclaw/traffic.jsonl
  Environment=MITM_RULES_PATH=/run/mitm/config/rules.json
  Environment=MITM_CREDENTIALS_PATH=/run/mitm/config/credentials.json
  Environment=MITM_IDENTITIES_PATH=/run/mitm/config/identities.json
  Environment=MITM_GRANTS_PATH=/run/mitm/config/grants.json
  Environment=MITM_PENDING_PATH=/run/mitm/config/pending.jsonl
  Environment=MITM_EXIT_PATH=/run/mitm/config/exit.json
  Environment=MITM_CONTENT_RULES_PATH=/run/mitm/config/content-rules.json
  Environment=MITM_LOGIN_TARGETS_PATH=/run/mitm/config/login-targets.json
  ExecStart=/opt/controlclaw/bin/cc-proxy --listen <private address>:8080
  ```

  - `MITM_TENANT` is the agent's `ORG_ID`. Without it every request reads as tenant `unknown`.
  - Without the paths, the proxy looks in `/config/` and refuses every request with
    `rules_unavailable`.
  - The proxy writes its traffic log to `MITM_LOG_FILE`. With no control plane, nothing ships it.
  - The CA is the one `packages/mitm-proxy/gen-ca.sh` writes (`mitmproxy-ca.pem`). Clients trust
    its `ca-cert.pem`.
- **Ports.** The agent's port 3100 listens on `MITM_AGENT_LISTEN`: loopback (`127.0.0.1`) in
  standalone mode, every address on a console firewall (where the cloud firewall closes it). On
  3100 a console firewall serves the archive its agents download at setup and the backup recovery
  routes. A standalone firewall uses neither, so 3100 stays on loopback; agents pair on 8801
  instead. Close 8080 to everything but the agents (a cloud firewall or `ufw`). The ingress (8790) is
  on loopback.

## The admin and the API

The agent serves a small API on `LOCAL_PANEL_BIND` (default `127.0.0.1:8800`). It speaks plain HTTP.
Reach it in one of these ways:

- an SSH tunnel to `localhost`;
- HTTPS in front of it on the same machine (Caddy with your domain, or Tailscale Serve).

| Setting | What it does |
| --- | --- |
| `LOCAL_PANEL_BIND` | Where the API listens. An address beyond loopback is refused at start, since the password and the setup token would cross the network in clear, unless `LOCAL_PANEL_INSECURE=1`. |
| `LOCAL_PANEL_HOSTS` | Comma-separated names the API is served under (for example the Caddy domain). A request whose `Host` is not one of these, loopback or the bind address gets 421. A web page whose name resolves to `127.0.0.1` (DNS rebinding) cannot reach the API through a tunnel. With a wildcard bind (`0.0.0.0`), list the addresses people use here too. |
| `LOCAL_PANEL_SECURE_COOKIE` | `0` drops `Secure` from the session cookie. By default it is Secure, which a browser keeps on `localhost` and over HTTPS. |

1. **First start.** There is no admin yet. The agent logs a one-time setup token:
   `[cc-local] no admin yet: set the password with this one-time setup token …`. Each start makes a
   new one, so only the newest line works.
2. **Setup.** `POST /api/setup {"token", "password"}` creates the admin. The password needs 12
   characters or more; it is stored as argon2id. The setup spends the token.
3. **Sign in.** `POST /api/login {"password"}` answers `{"csrf"}` and sets the `cc_local_session`
   cookie (HttpOnly, SameSite=Strict, Secure, 12 hours; only its hash is stored).
   - Every write sends the token back as `x-csrf-token`.
   - Each try counts before the password is checked: ten a minute from one address, thirty from
     everyone, then 429 for the rest of the minute. A success takes back only its own try.
   - Someone who can reach the API can use up the shared thirty with wrong passwords and keep the
     admin out, minute after minute. That is the price of the cap; keep the API on loopback.
   - Behind an SSH tunnel or a reverse proxy, every client has `127.0.0.1`'s address and shares
     one budget.
   - At most two password checks (argon2, 19 MiB each) run at once.

| Call | What it does |
| --- | --- |
| `GET /api/session` | `{admin, setup, csrf}`: signed in, still needs setup. |
| `GET` / `PUT /api/egress-rules` | The rules; `PUT {"rules": [...]}` replaces them all. The proxy has them on the next sync. |
| `GET` / `PUT /api/agents` | The agents (`vm_id`, `name`, `private_ip`, `hostname?`, `role?`); `PUT` replaces them, paired ones included. Pairing adds one at a time. |
| `POST /api/pairing/codes` | `{"name"?, "ttl_minutes"?, "address"?, "replace"?}`: a one-time pairing code (below), `{id, code, name, address, replace, expires_at}`. |
| `GET /api/pairing/codes` | The codes still waiting, without the codes. |
| `DELETE /api/pairing/codes/<id>` | Revokes a waiting code. |
| `GET /api/permissions` | The last 100 permission requests, each with its `id`. |
| `POST /api/permissions/answer` | `{"id", "resolution": "approved" \| "denied"}`. The `id` is the request's own: a box's `permission_id` is only unique to that box. A request whose time ran out is not approved (409). |
| `GET /api/activity/recent?limit=` | The newest activity rows. |
| `POST /api/commands` | `{"action", "payload"}`: runs the firewall's handler for that action at once, with no queue. The payload is checked against its type in `cc-contracts`. A SaaS-only action is refused (403), and so are `start`, `stop` and `restart`: the service unit is the install's, run with `systemctl`. The handler runs as the signed-in admin: a change applies with no code sent to anyone ([`panel-api.md`](panel-api.md#no-confirmation-codes)); a `<module>.propose` is confirmed at once, as the panel's routes do. The payload's secrets are remembered for redaction, and a handler that fails is a failed answer. |
| `POST /api/open` | `{"page"}`: a link to one of the firewall's pages, as `mitm-agent open` makes. |
| `POST /api/logout` | Ends every session of the admin. |

The panel's own calls (rules one by one, AI review, model keys, activity and the overview) are in
[`panel-api.md`](panel-api.md), and the panel itself, served on the same address, in
[`panel.md`](panel.md).

## Pairing an agent

An agent's machine joins with a one-time code. The CLI's side, and why the code is safe on plain
HTTP, are in [`packages/cli/README.md`](../../packages/cli/README.md#pairing).

- **The address.** The panel's pairing command names `PAIR_PROXY_ADDR`'s host and `PAIR_BIND`'s
  port, and `WG_ENDPOINT`'s host for machines on another network (`GET /api/pairing/address`).
  Without `PAIR_PROXY_ADDR`, it uses the page's own host, or `<firewall address>` on localhost.
- **A code.** `mitm-agent pair-code [--name N] [--ttl M] [--address IP] [--replace]`, run as the firewall's user, prints one
  (`4F7K-92QD-XM3P`: 12 characters of Crockford base32, 60 bits). It reads only `STATE_DIR` and
  writes into the running firewall's `local.db`, so it works only on a standalone firewall that has
  started. The admin API makes codes too. A code works once, within 10 minutes (at most 60), and
  at most 20 wait at a time.
- **The endpoint.** `POST /pair` on `PAIR_BIND` (default `0.0.0.0:8801`; `off` closes it), with no
  login. It takes `{request, proof}`, where `request` is a JSON string
  (`{v: 1, nonce, agent_public_key, name?, source, unpair_sha256?, wg_public_key?, agent_listen?}`;
  without `source`, 400 before any code is tried) and `proof` its HMAC-SHA256 under the code. It
  answers `{pairing, mac}` the same way: `pairing` holds the agent's id, its name and address, this
  firewall's public key (`KEYS_DIR/vm_public_key.pem`), its CA (`CA_CERT_PATH`), and
  `PAIR_PROXY_ADDR` and `PAIR_DNS_ADDR` when they are set.
  - The code never crosses the network, so plain HTTP is safe: see the CLI README.
  - Ten wrong codes a minute from one address, and it answers 429 there for the rest of the minute.
    A try is counted before the code is checked, so parallel requests do not get past it.
  - Not served in SaaS mode.
- **What it records.** A row in `agents`: `vm_id` `agent_<16 hex>`, role `openclaw`, the name (the
  code's, else the request's, else the id), `private_ip`, the vm-agent's public key and `paired_at`.
  - `private_ip` is the code's `address` when the admin set one. Otherwise it is the address the
    request came from, which must equal the request's `source` (the machine's own address, under the
    proof): a request replayed from elsewhere, or through a NAT the code does not name, is refused.
  - IPv4 only; not loopback, unspecified, multicast, broadcast or the firewall's own (checked before
    any code is tried, or when the code is made).
  - An agent already at that address is replaced only when the code says `replace`; the answer's
    `replaced` names it. The proxy names traffic by source address alone.
  - Once a code has matched, any refusal spends it and counts as a failure, so a refusal confirms
    nothing.
  - `POST /unpair {agent_id, secret}` removes an agent whose `unpair_sha256` is the secret's
    sha256 (the CLI does this on `disconnect`): the same 404 for an unknown agent and a wrong secret,
    which count like wrong codes.
  - `agent_listen` (`ip:port`) is where the agent's vm-agent listens, kept as `agents.agent_addr`.
    The firewall calls the vm-agent there directly, in plain HTTP, with the same signed tokens as on
    the SaaS (signed for that address), and the vm-agent takes connections from the firewall's
    address only (`firewall.allow_from`). So it is only for a path nobody else is on:
    - over WireGuard (remote mode): the agent's tunnel address and 3100, always; `agent_listen` is
      refused with `wg_public_key`;
    - on the firewall's own machine (`up --all`, docker mode, host with the firewall in a container
      here): `agent_listen` must be the request's `source`, or, when the code names the agent's
      address, that address (for an `up --all` container, named on `172.31.251.0/24`: the host's
      side of `outside`, `172.31.252.1`);
    - never loopback, link-local (the clouds' metadata service) or one of the firewall's own
      addresses (`/proc/net/fib_trie`).

    A WireGuard agent keeps its tunnel address: `PUT /api/agents` refuses to move it.

    An agent with neither (paired across a network in host, proxy or docker mode) gets no calls:
    bots, models and the emergency stop need remote mode there. Agents paired before
    `agent_listen` existed have no address for calls either: run `controlclaw connect` again.
  - A bot's token never goes to the agent on a standalone firewall: the agent gets a stand-in, and
    the proxy puts the token in on the way to Telegram or Slack (`CHANNELS_PLACEHOLDER_SWAP` is
    always on here). The stand-ins are shaped as the tokens: the bot's id first for Telegram (the
    proxy's Telegram check reads it from the path), `xoxb-` and `xapp-<n>-<app id>-` for Slack.
    A firewall upgraded from a build before this one still has the real tokens on its agents: save
    each bot's token once more (`PUT /api/channels/{id}/token` with the same token), and the agent
    gets the stand-in.
  - Migrations 2 and 3 add `pairing_codes` and `agents.paired_at`, then the code's `address` and
    `replace` and `agents.unpair_sha256`. A later one adds `agents.agent_addr`.
  - The proxy knows the new agent at its next sync (`SYNC_INTERVAL_MS`, a minute). `PUT
    /api/agents` keeps an agent's key, `paired_at` and `agent_addr` when the list names it by its
    `vm_id` (an `agent_addr` in the list replaces it).
- `install.sh` sets `PAIR_PROXY_ADDR` to its `--listen` address and port 8080. In Docker, set it to
  the proxy's address as the agents reach it, and publish 8801 where they reach it.

## WireGuard for remote agents

An agent on another network (another cloud, a home server) reaches the firewall over WireGuard. Its
tunnel address is its identity at the proxy.

- **On the firewall.** `install.sh --wireguard [--wg-endpoint host[:port]] [--wg-address 10.77.0.1/24]`,
  or the image with `CC_WIREGUARD=1`, `WG_ENDPOINT` and `cap_add: NET_ADMIN` (the host needs the
  WireGuard module). Either one:
  - makes the interface `cc-wg0` with a key only root reads, and writes its public half to
    `KEYS_DIR/wg_public_key`;
  - has the proxy and DNS listen on the tunnel address too;
  - loads nft rules: from the tunnel, only the proxy (8080) and DNS (53) on the firewall's tunnel
    address, and answers to what the firewall started; nothing is forwarded;
  - with ufw active (`install.sh`), allows the tunnel's proxy and DNS and UDP 51820 in ufw (comment
    `controlclaw-wg`; removed with the tunnel): ufw's own chain drops what its rules do not allow,
    whatever the firewall's rules accept;
  - gives the firewall agent `WG_ENDPOINT`, `WG_ADDRESS` and `WG_PROXY_PORT` (the proxy's own port,
    which the tunnel reaches directly, not one Docker publishes). WireGuard is off without
    `WG_ENDPOINT`, whatever the keys folder holds; setting the firewall up again without it removes
    the tunnel and the public key file.
  - The tunnel's address is a /24. The proxy keeps trying to listen on it when the interface is not
    up yet, without taking its other address down.
- **Pairing.** A request with `wg_public_key` gets a free tunnel address from `.2` (not the
  firewall's, not an agent's), recorded as the agent's `private_ip` with its key in `agents.wg_public_key` (migration 5).
  The answer's `wg` has the firewall's WireGuard key, endpoint and tunnel address; its proxy and DNS
  are the tunnel address. A code made with `--address` is refused for these (and spent). The address
  the request came from is not checked for these: behind a NAT
  it differs, and a replayed request would register a key only the real machine has. A firewall
  without WireGuard refuses them (the code is spent).
- **Peers.** The firewall agent writes the peers to `WG_PEERS_PATH` (default `STATE_DIR/wg-peers.conf`)
  within seconds of a change (pairing, unpairing, `PUT /api/agents`). Root applies them with
  `wg syncconf` (`controlclaw-wg-sync.path`, or a loop in the image), with these limits:
  - only a `[Peer]` with one `PublicKey` and one `/32` `AllowedIPs` from `.2` to `.254` of the tunnel
    network (no leading zeros, never the firewall's own);
  - each key and each address once;
  - only a regular file, not a link or a FIFO, at most 1 MiB, read within 30 seconds and 64 MB.
- **One key, one agent.** A WireGuard key pairs once (409 for a key the firewall has; a unique index
  in migration 5), and the peers file lists each key once.

## The node relay (spike)

`NODE_RELAY=<listen host:port>=<gateway host:port>` makes the firewall agent relay an OpenClaw node's
WebSocket to the gateway, frame by frame. With `NODE_RELAY_TLS=<cert.pem>,<key.pem>` it serves
`wss://`. It logs which node connected and what the gateway asked it to run, to the journal, and
enforces nothing. Off when unset, and never on in SaaS mode.

- It resolves the gateway's name for each node, checks every address it gives, and connects to the
  address it checked. A name that does not resolve yet is tried again with the next node.
- It refuses a gateway on loopback or an unspecified address, in any spelling.
- Its leg to the gateway is plain `ws://`, so a public gateway address needs `NODE_RELAY_INSECURE=1`.
  So does plain `ws://` toward the nodes beyond loopback.
- At most 64 nodes at once.
- A node's first `connect` is logged only after the gateway answers it with `hello-ok`, and no result
  counts before that. A connect the relay cannot read is logged as such once the gateway accepts it.
  Every logged field is capped. Other frames over 64 KiB are passed on without being read.

How to set it up: [`desktop-app.md`](desktop-app.md).

## Opening a page

Two of the firewall's own pages open this way: `firewall-logs` and `logins`. The content rules are
set through the panel's API (`panel-api.md`). AI review is an agent's page.

On the firewall, as the user that reads `KEYS_DIR`, run:

```bash
mitm-agent open logins
```

It reads only `KEYS_DIR` from the environment, and refuses with "standalone only" when the agent
does not run standalone. The organization and id come from
`local_intent_identity.json`, which the running agent writes there at start.

It prints a link of the form `https://<name>/__cc/local/open#i=…`.

- `<name>` is in `KEYS_DIR/vm_hostname`. Put the name your browser reaches the firewall at there,
  behind Caddy, Tailscale Serve or an SSH tunnel.
- The link works once, within 60 seconds. When one is refused, the agent's log says why.
- The browser that opens it is enrolled for the firewall's pages and sent on to the page.

How it works:

- At first start the firewall makes a key pair in `KEYS_DIR`: `local_intent_key.pem` and
  `local_intent_public.pem` (written back if it goes missing).
- `open` signs an Open intent with that key, the same kind of intent the console signs with its own.
- The firewall checks the intent against the public half instead of `saas_public_key.pem`.
- Anyone who can read the key can make links, so keep `KEYS_DIR` readable by root only.

After that, the rest of the flow is the SaaS one: a session cookie per page and the enrolled-browser
check. Browsers enrolled this way are listed with `via: local`. `POST /api/open` signs the same
intents for a signed-in admin.

## Checked on real servers

On 2026-10-30, before the local control plane existed (the policy was in files), two Hetzner cx23
servers on one private network ran a test:

- **The firewall** ran `mitm-agent` (standalone) and `cc-proxy` from `build-box.sh`, as systemd units,
  with no Ansible and no console.
- **The client** sent `curl -x http://<firewall>:8080 --cacert ca-cert.pem` requests:
  - example.com was let through by its allow rule;
  - example.org was refused by its block rule (403 `blocked_by_policy`);
  - a host no rule names was let through (the default, as in the SaaS);
  - each request was in the traffic log with the client's `vm_id` from `identities.json`;
  - a block rule added to `egress-rules.json` took effect on the next sync.
- **The pages.** `mitm-agent open logins` enrolled a browser and opened the logins page.
- **Refusals.** A bad `MITM_MODE` and an `https` `FIREWALL_URL` stopped the agent with the reason.

## What does not change

- With `MITM_MODE` unset or `saas`, nothing above applies. The console's firewalls start, sync,
  beat and open pages exactly as before.
- The conformance cases for the SaaS build run unchanged.
- `rust/conformance/cases/standalone/` holds the standalone cases. They are Rust only; the Node build
  has no standalone mode.
