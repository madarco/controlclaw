# Troubleshooting

Start with these two commands. They usually say what is wrong:

```bash
controlclaw doctor          # what this machine can do, and why a mode is refused
sudo controlclaw status     # whether the capture, the vm-agent, and the firewall's proxy and DNS are up
```

If `connect` ran with `sudo`, run `status` and `disconnect` with `sudo` too.

## OpenClaw can't reach anything

- **Every other site is set to Block.** A new firewall allows every site. A firewall installed before
  November 2026 started with every other site blocked, and keeps that setting. With Block, only your
  rules let traffic through, plus the rules the firewall adds for the model keys and bots you set up
  in the panel. A key typed into OpenClaw itself, not into the panel, has no rule. Add one for its
  host (for example `api.openai.com`) in **Internet access**, or set **Every other site** to
  **Allow**. The proxy gets the change at once.
- **The firewall is down, or can't be reached.** Captured traffic then fails; it does not go around
  the firewall. `status` shows which check fails. On the firewall, look at its services:
  - install script: `systemctl status controlclaw-mitmproxy controlclaw-dns`;
  - `install`, `up --here`: `sudo docker compose -p controlclaw-firewall logs firewall`;
  - `up --all`: `sudo docker compose -p controlclaw-local logs firewall`.
- **The CA is not trusted yet.** Node reads the CA only when it starts, so `connect` restarts OpenClaw.
  For a systemd unit, `connect` also sets `NODE_EXTRA_CA_CERTS` for it. Under pm2 or as a plain
  process it can't. Add `NODE_EXTRA_CA_CERTS=/etc/controlclaw/ca.crt` (`~/.config/controlclaw/ca.crt`
  when `connect` ran without sudo) to pm2's ecosystem file or to how you start OpenClaw, then restart
  it.

## DNS stopped on the whole machine (host and remote mode)

Host and remote mode point systemd-resolved at the firewall, and only at it. When the firewall stops,
every program on the machine loses DNS, not only OpenClaw. Start the firewall again, or run
`sudo controlclaw disconnect` to put the machine's DNS back.

## The capture is gone after a while (host and remote mode)

`status` says the nftables table is missing.

- `nftables.service` flushes the whole ruleset when it starts, restarts, reloads or stops. `connect`
  adds a drop-in that loads ControlClaw's rules again after each of those.
- Anything else that flushes the ruleset removes them: `nft flush ruleset`, or `nft -f` with a file
  that starts with `flush ruleset` (some firewall tools do this). Load the rules again with
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

- **The code was used or expired.** A code works once, within 10 minutes. Make a new one in the panel
  (**Agents**, **Connect an agent**). Any refusal after the code matched also spends it.
- **429.** More than ten wrong codes came from one address in a minute. Wait a minute.
- **The address is refused.** The firewall checks that the request comes from the address the
  machine says it has. Behind a NAT, make the code with the address the proxy will see: in the panel
  under **More options**, **Address the proxy sees**, or with `--address` on `mitm-agent pair-code`.
  Remote mode does not need it.
- **An agent is already at that address.** Remove it with the API (`PUT /api/agents`, see
  [standalone-mode.md](standalone-mode.md#the-admin-and-the-api)), or tick **It may take the place of
  an agent already at its address** under **More options** when you make the code.

## Remote mode: no handshake

`connect --mode remote` waits about 45 seconds for the firewall's first WireGuard answer, then stops
and undoes everything. Something on the way blocks UDP to the firewall's port 51820:

- open UDP 51820 on the firewall, in its cloud firewall too, not only in ufw;
- check that the endpoint `install.sh --wireguard` printed is the address agents reach (set
  `--wg-endpoint` when it is not the machine's own).

## Docker: published ports and port 53

- Docker's published ports go around ufw, because Docker writes its own rules. Publish the proxy and
  DNS (`CC_LISTEN`) only on an address that only your agents reach. Never use a public one.
- The container does not start when port 53 on `CC_LISTEN` is taken. systemd-resolved's stub listens
  on 127.0.0.53, so 127.0.0.1 is free, but another resolver may hold it. Free the port, or set
  `CC_DNS_PORT` to another port. The capture modes send DNS to port 53 only, so for them use an
  address where 53 is free.

## The panel

- **Where is the setup token?** `controlclaw open` on the firewall's machine gives the panel's link
  with the newest token in it (use sudo for a firewall from the install script). The firewall's log
  also has it, at each start while there is no admin. Only the newest one works.
  - install script: `sudo journalctl -u controlclaw-mitm-agent | grep 'no admin yet'`
  - `install`, `up --here`: `sudo docker compose -p controlclaw-firewall logs firewall | grep 'no admin yet'`
  - `up --all`: `sudo docker compose -p controlclaw-local logs firewall | grep 'no admin yet'`
- **`install` refuses: something already listens on 127.0.0.1:8800.** Another firewall runs on this
  machine (`install.sh`, `up --all`, `standalone/docker`). Remove it, or keep it and connect OpenClaw
  to it. A firewall from `up --all` already has its own OpenClaw. For the others, run
  `controlclaw connect --firewall http://<its address>:8801` with a code from its panel.
- **`install` refuses rootless Docker.** Rootless Docker's networks live in a namespace of their own,
  where this machine has no address for the vm-agent. Use Docker run by root (your user in the
  `docker` group is enough).
- **Too many tries.** The panel allows ten sign-in tries a minute from one address, and thirty from
  everyone. Wait a minute. Behind an SSH tunnel, every browser shares one address.
- **421.** The panel answers only to the names it knows. Add yours to `LOCAL_PANEL_HOSTS`: in
  `/etc/controlclaw/firewall.env` for the install script (then run
  `sudo systemctl restart controlclaw-mitm-agent`), or in the firewall's `environment:` in your
  compose file for Docker.

## Host mode: the ChatGPT/Codex provider does not work

OpenClaw's Codex relay listens on a random local port, which host mode's rules refuse. Use Docker
mode for it.

## Undo everything

```bash
sudo controlclaw disconnect     # puts back every file and setting connect changed
```

A step that fails stays recorded, so you can run `disconnect` again once you fix the cause.
`disconnect --force` gives up such steps and lists what to check by hand.
