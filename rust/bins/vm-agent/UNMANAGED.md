# vm-agent: unmanaged mode

In unmanaged mode the vm-agent works with an OpenClaw that was installed some other way: the
official installer, Docker, pm2, or by hand. A managed box (one our Ansible role set up) runs the
agent as before. Linux only for now.

## How the mode is chosen

The agent reads `CC_AGENT_CONFIG` (default `/etc/controlclaw/agent.json`).

- No file: managed mode, unchanged.
- A file with `"mode": "unmanaged"`: unmanaged mode.
- Anything else in the file (another mode, an unknown key, bad JSON): the agent exits with the reason.

## The config file

```json
{
  "mode": "unmanaged",
  "listen": "127.0.0.1:3100",
  "state_dir": "/home/claw/.local/state/controlclaw",
  "agent_id": "vm_1",
  "firewall": {
    "url": "https://fw.example.com",
    "public_key": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----\n",
    "hostnames": ["agent-1.fw.example.com"],
    "allow_from": ["10.0.0.2"],
    "gate": "10.0.0.2"
  },
  "openclaw": {
    "cli": "/home/claw/.npm-global/bin/openclaw",
    "state_dir": null,
    "runs": "auto",
    "unit": null,
    "container": null,
    "pm2_name": null,
    "gateway_port": null
  }
}
```

Only `mode` is required.

| Field | What it does |
| --- | --- |
| `listen` | Where the agent listens. Default `127.0.0.1:3100`. An address that is not on the machine yet (a tunnel or a Docker bridge that comes up later) is tried again every 2 s. |
| `state_dir` | The agent's own files: session secret, keypair, channel state. Default `~/.local/state/controlclaw`. |
| `agent_id` | The id the firewall gave this agent. Once set, tokens must name it. |
| `firewall.public_key` | The firewall's Ed25519 public key (PEM). It opens every route (see below). |
| `firewall.url` | Shown on `/status`. Nothing calls it yet. |
| `firewall.gate` | The firewall's address as OpenClaw reaches it: MCP servers are written at its 3940 gate there, and the app-connection relay dials its 3900 gate there (the tunnel's address, the proxy's, or a container's gate). Without it, MCP servers must be on a `10.x` address, as on a managed box. |
| `firewall.allow_from` | The only addresses that may connect: the firewall, as it reaches this machine. A connection from any other is closed before anything is read. Without any, every address may (tokens are still needed). |
| `firewall.hostnames` | The names the firewall signs this agent's tokens for. Once one bound token was taken, a token for another name is refused. Without any, the name is not checked (the agent logs this once at start). |
| `openclaw.*` | Overrides what discovery finds. `runs` is one of `auto`, `systemd-user`, `systemd-system`, `docker`, `pm2`, `process`. |

Pairing (`controlclaw connect --code`) writes `listen`, `firewall` and `agent_id`. The firewall calls
the agent at the `listen` it was told at pairing (`agent_listen`), over plain HTTP, with tokens signed
for that address (so `firewall.hostnames` is that address). Without pairing the file can be written by
hand.

## Who can call it

There is no control plane. The firewall's key opens both kinds of route:

- firewall routes (`POST /llm/apply`, `POST /channels/apply`, ...) take the firewall's bound
  tokens, as on a managed box;
- the routes the console calls on a managed box (`/status`, `/health`, `/start`, `/stop`,
  `/restart`) take a token without a `purpose`, signed by the same key. In a standalone setup the
  firewall is the control plane.

With no `firewall.public_key` the agent still starts, logs that it is waiting for pairing, and answers
401 to everything.

## What it finds

`vm-agent discover` prints what the agent would find, as JSON, with or without a config file. It
writes nothing, so it is safe on any box:

```json
{
  "cli": "/home/claw/.npm-global/bin/openclaw",
  "version": "2026.10.9",
  "config_file": "/home/claw/.openclaw/openclaw.json",
  "state_dir": "/home/claw/.openclaw",
  "runs": { "kind": "systemd-user", "unit": "openclaw-gateway.service" },
  "gateway_port": 18789
}
```

`GET /status` shows the same under `install`, with `state` (`running`, `starting`, `stopped`) and
`firewall: { url, paired }`.

In order:

1. **Docker.** A running container whose image is OpenClaw's (`docker ps`), or `openclaw.container`.
   The CLI is `docker exec -i <container> node dist/index.js`. The gateway port is the host port
   published for 18789, and the config and state paths are shown as the host sees them, through the
   container's mounts.
2. **The CLI.** `openclaw.cli`, `$OPENCLAW_BIN`, `PATH`, then where the installers put it
   (`~/.openclaw/bin`, `~/.npm-global/bin`, `~/.local/bin`, `/usr/local/bin`, `/usr/bin`).
3. **Version and config:** `openclaw --version` and `openclaw config file --json`.
4. **How it runs:** `openclaw gateway status --json`. The official installer sets up a systemd user
   unit, `openclaw-gateway.service`. If OpenClaw sees only a process, `pm2 jlist` is checked.
   Otherwise it is a plain process, or not running.

Every discovery keeps `<state_dir>/openclaw` up to date: a small script that runs the CLI it found
(or the one in the container). The agent runs OpenClaw commands through it, so an OpenClaw installed
or moved after the agent started is picked up without a restart. While nothing runs, the agent looks
again every minute, and after every start or restart. The script is replaced whole, only when it
changes, and one look that finds no CLI does not replace a script that points at one.

## What it does

| | How |
| --- | --- |
| Write config | `openclaw config patch --stdin`: the same merge patch the managed agent sends the gateway. The gateway reloads the file itself and restarts itself when a setting needs it. |
| Read from the gateway | `openclaw gateway call <method> --json`. The CLI signs in with OpenClaw's own settings, so the agent holds no gateway token. |
| Models | `models auth paste-api-key` and the other model commands, through the same CLI. |
| Restart (systemd user unit, plain process) | `openclaw gateway restart` |
| Start and stop (systemd user unit) | `systemctl --user start\|stop <unit>`: `openclaw gateway stop` refuses with no terminal, and `gateway start` waits longer than the firewall's call |
| Restart (systemd system unit) | `sudo -n systemctl restart <unit>`: the owner allows this one command in sudoers, or the refusal is shown |
| Restart (Docker) | `docker restart <container>` |
| Restart (pm2) | `pm2 restart <name>` |
| Gateway up? | `GET /healthz` on the gateway port, every 5 seconds. |

The agent never edits OpenClaw's files directly.

A write through the CLI carries no base hash, as a write to the gateway does. The agent's own writes
go one at a time, but a setting changed in OpenClaw itself (its Control UI, the CLI, another tool)
while the agent writes the same part of the config can be overwritten without notice.

Gateway calls pass their parameters as `--params <json>` (OpenClaw has no other way), so another
user on the same machine can read them in the process list while a call runs.

## What is on and what is off

On: `/health`, `/status`, `/start`, `/stop`, `/restart`, `/llm/*` (models), `/channels/*`,
`/kill/*` (the firewall's emergency stop: OpenClaw stopped and started the way it runs), and:
- `/search/*`: the provider's plugin and key, through the CLI discovery found. Stock OpenClaw has
  no Tavily or Brave plugin: install it first (`openclaw plugins install @openclaw/tavily-plugin`),
  or the push answers which one is missing;
- `/secrets/*`: the placeholders in OpenClaw's own `.env`, then a restart the way it runs. In a
  container the file is read and written inside it (`docker exec`, as the container's own user);
  on this machine, by the agent as OpenClaw's user (refused as root), following no link;
- `/mcp-servers/*`: each server at the firewall's gate on `firewall.gate`;
- `/connectors/*`: the relay on `127.0.0.1:3111` to the 3900 gate on `firewall.gate`. Not for an
  OpenClaw in a container yet: it cannot reach this machine's loopback, so those routes answer 503.

Off: everything that needs our Ansible role or the SaaS: the bootstrap (CA install, `cc-install-ca`,
egress, register, ready report), the pool, templates, backups, gbrain, disk and storage, Doctor,
the watchdog, update, meetings, phone, the agent's own pages and sign-in, files, website logins,
Drive, Google, AgentMail, SSH, Tailscale, logs, skills, and the activity, metrics, audit and
approvals reports.

## Running it

Run the agent as the same user as OpenClaw, so it can use the CLI and the user's systemd without sudo.
For an OpenClaw in Docker, that user must be in the `docker` group.

```ini
# ~/.config/systemd/user/controlclaw-agent.service
[Unit]
Description=ControlClaw agent (unmanaged)
After=openclaw-gateway.service

[Service]
ExecStart=/usr/local/bin/vm-agent
Restart=always
RestartSec=5

[Install]
WantedBy=default.target
```

```bash
loginctl enable-linger "$USER"   # keep user services running after logout
systemctl --user daemon-reload
systemctl --user enable --now controlclaw-agent.service
```

## A container's folder

For a Docker install the agent runs as root, and OpenClaw's state folder belongs to the container.
The agent never walks it on this machine: what it reads there (the channels' `credentials/*-pairing.json`
and `state/openclaw.sqlite` with its log) is copied out with `docker cp -L <container>:<path> -`,
and what it writes (the secrets' `.env`) goes through `docker exec`. Both resolve paths and links
inside the container. A copy is taken only as one regular file from that tar (no folder, link or
device node, nothing of its mode or owner), at most 64 MB for the database and its log and 1 MB
otherwise (a larger one is not read, and the log says so), written 0600 in a folder of its own
(0700) under the agent's `from-container`, and removed once read; a `docker cp` that takes over
20 s is stopped. The pairing files of gateways before 2026.9 are not read in a container. The
`.env` is read and written up to 1 MB, as UTF-8 text; a read that fails is an error, never an empty
file. A path the container names that no mount holds, or one with `..`, is not
mapped to this machine at all; with no folder known, nothing is copied or written there.

## Gotchas

- **Docker group.** A user's systemd manager keeps the groups it started with. After adding the user
  to `docker`, restart it (`sudo systemctl restart user@$(id -u)`) or log in again.
- **No `agent_id`.** Without it, tokens are checked by signature only, so one firewall key opens every
  agent that has it. The agent logs a warning. Pairing sets the id.
- **Startup repairs.** The Docker image runs `openclaw doctor --fix` at every start. It can rewrite
  settings, such as a retired model id moved to its successor. The setting comes back, under
  OpenClaw's new name.
- **Slow CLI.** Each OpenClaw command starts Node, which takes a few seconds (`config patch` took 7 s
  on a 4 GB box). A model change takes about 25 seconds in all.

## macOS (not built)

A Mac needs a proxy-only mode:

- discovery for launchd (OpenClaw's `ai.openclaw.gateway` LaunchAgent; `openclaw gateway restart`
  already drives it), with the CLI from Homebrew or npm;
- OpenClaw's own proxy settings (`proxy.enabled`, `proxy.proxyUrl`, `proxy.tls.caFile`), written
  through the same CLI writer, instead of capture rules;
- the firewall's CA in the login keychain;
- a macOS build of the agent: no `/proc`, no systemd, no Linux-only file system calls.
