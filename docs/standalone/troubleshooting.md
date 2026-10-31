# Troubleshooting

Start with these two. They say what is wrong more often than not:

```bash
controlclaw doctor          # what this machine can do, and why a mode is refused
sudo controlclaw status     # whether the capture, the vm-agent, and the firewall's proxy and DNS are up
```

Run `status` and `disconnect` with `sudo` when `connect` ran with it.

## OpenClaw cannot reach anything

- **The firewall blocks everything until you allow it.** A new firewall starts with one rule: block
  all. Open the panel, **Internet access**, and allow your model provider (for example
  `api.openai.com`) and the sites the agent needs. The proxy has the change at once.
- **The firewall is down, or not reachable.** Captured traffic then fails; it does not go around.
  `status` shows which check fails. On the firewall: `systemctl status controlclaw-mitmproxy
  controlclaw-dns` (VM), or `sudo docker compose -p controlclaw-local logs firewall` (`up --local`).
- **The CA is not trusted yet.** Node reads the CA only when it starts. `connect` restarts OpenClaw.
  For a systemd unit it also sets `NODE_EXTRA_CA_CERTS` for it. Under pm2 or as a plain process it
  cannot: add `NODE_EXTRA_CA_CERTS=/etc/controlclaw/ca.crt` (`~/.config/controlclaw/ca.crt` when
  `connect` ran without sudo) to pm2's ecosystem file or to how you start OpenClaw, and restart it.

## DNS stopped on the whole machine (host and remote mode)

Host and remote mode point systemd-resolved at the firewall, and only at it. When the firewall stops,
every program on the machine loses DNS, not only OpenClaw. Start the firewall again, or run
`sudo controlclaw disconnect` to put the machine's DNS back.

## The capture is gone after a while (host and remote mode)

`status` says the nftables table is missing.

- `nftables.service` flushes the whole ruleset when it starts, restarts, reloads or stops. `connect`
  adds a drop-in that loads ControlClaw's rules again after each of those.
- Anything else that flushes the ruleset removes them: `nft flush ruleset`, or `nft -f` with a file
  that starts with `flush ruleset` (some firewall tools do this). Load them again with
  `sudo systemctl restart controlclaw-capture`, and stop that tool from flushing.

## connect refuses the mode

The message says why. The common ones:

| Message | Fix |
| --- | --- |
| OpenClaw runs as root | Run OpenClaw as its own user (host and remote mode), or use Docker or proxy mode. |
| OpenClaw's user is in the `docker` group | `sudo gpasswd -d <user> docker`, then log in again; or use Docker mode. |
| the gateway mounts `docker.sock`, is `privileged`, has `NET_ADMIN` … | Remove that from its compose file, then connect again. |
| other services of the Compose project run with the gateway | They would lose their network. Run them in another project. |
| Compose older than 2.24.4, or Docker older than 28 | Update Docker. |
| `172.31.250.0/24` (or `.251`, `.252`) is in use | Another Docker network has it. Remove that network. |
| OpenClaw already has a proxy setting (proxy mode) | Remove the `proxy` block from OpenClaw's config, then connect. |
| a folder on the way is writable by others | `sudo chmod go-w <folder>`, as the message says. |

## Pairing fails

- **Code used or expired.** A code works once, within 10 minutes. Make a new one in the panel
  (**Agents → Connect an agent**). Any refusal after the code matched also spends it.
- **429.** More than ten wrong codes a minute from one address. Wait a minute.
- **Address refused.** The firewall checks that the request comes from the address the machine says
  it has. Behind a NAT, make the code with the address the proxy will see (**Agents → Connect an agent →
  More options → Address the proxy sees**, or `--address` with `mitm-agent pair-code`). Remote mode does not
  need it.
- **An agent is already at that address.** Remove it with the API (`PUT /api/agents`,
  [standalone-mode.md](standalone-mode.md#the-admin-and-the-api)), or tick "It may take the place of an agent already at its address" under **More options** on
  the code.

## Remote mode: no handshake

`connect --mode remote` waits about 45 seconds for the firewall's first WireGuard answer, then stops
and undoes everything. UDP to the firewall's port 51820 is blocked on the way:

- open UDP 51820 on the firewall (its cloud firewall too, not only ufw);
- check the endpoint `install.sh --wireguard` printed is the address agents reach
  (`--wg-endpoint` when it is not the machine's own).

## Docker: published ports and port 53

- Docker's published ports go around ufw: Docker writes its own rules. Publish the proxy and DNS
  (`CC_LISTEN`) only on an address that only your agents reach. Never a public one.
- The container does not start when port 53 on `CC_LISTEN` is taken (systemd-resolved's stub listens
  on 127.0.0.53, so 127.0.0.1 is free; another resolver may not be). Free it, or set `CC_DNS_PORT` to
  another port. The capture modes send DNS to port 53 only, so for them use an address where 53 is
  free.

## The panel

- **Where is the setup token?** In the firewall's log, at each start while there is no admin:
  `journalctl -u controlclaw-mitm-agent | grep 'no admin yet'` (VM) or
  `sudo docker compose -p controlclaw-local logs firewall | grep 'no admin yet'` (`up --local`). Only the newest one works.
- **Too many tries.** Ten a minute from one address, thirty in all. Wait a minute. Behind an SSH tunnel
  every browser shares one address.
- **421.** The panel answers only to the names it knows. Add yours to `LOCAL_PANEL_HOSTS`: in
  `/etc/controlclaw/firewall.env` (install script; then `sudo systemctl restart controlclaw-mitm-agent`),
  or in the firewall's `environment:` in your compose file (Docker).

## Host mode: the ChatGPT/Codex provider does not work

OpenClaw's Codex relay listens on a random local port, which host mode's rules refuse. Use Docker
mode for it.

## Undo everything

```bash
sudo controlclaw disconnect     # puts back every file and setting connect changed
```

A step that fails stays recorded, so you can run it again once the cause is fixed.
`disconnect --force` gives up such steps and lists what to check by hand.
