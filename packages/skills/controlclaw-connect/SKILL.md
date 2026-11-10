---
name: controlclaw-connect
description: Put this OpenClaw behind a ControlClaw firewall with a pairing code from its owner. Use when the person asks you to connect to their ControlClaw firewall, gives you a pairing code (like 4F7K-92QD-XM3P), or asks what the firewall would protect on this machine.
---

# Connect to a ControlClaw firewall

A ControlClaw firewall is a proxy the person runs. Once this machine is connected, everything
OpenClaw sends to the internet goes through it, and it applies the person's rules. The `controlclaw`
command line tool does the connecting. You run it, but the person decides: **ask before you change
anything**.

Connecting limits what you can do from then on. That is the point: do it only when the person asks,
and never undo it or get around it later.

## 1. Check the tool

```bash
controlclaw --version
```

If it is not found, stop and tell the person to install it, then ask you again:

```bash
npm i -g controlclaw
```

**If you run inside a container** (`/.dockerenv` exists, or the person says OpenClaw runs in
Docker), this skill cannot do it from here: the tool, the machine's Docker and its root are outside
your container. Tell the person to run, on the machine itself, `controlclaw doctor`, then
`sudo controlclaw connect --mode docker --firewall <address>` (it asks for the code), and explain the
protection with the table below. Or `controlclaw up --local` for a new OpenClaw behind its own
firewall. Stop there.

## 2. Look at the machine

```bash
controlclaw doctor --json
```

It needs no root and changes nothing. Read three parts of its output:

- `modes`: each mode, whether this machine can do it (`ok`), why not (`blockers`), and how much it
  protects (`protects`). You run `doctor` without root, so `docker`, `host` and `remote` show the
  blocker `needs root (run it with sudo)`. A mode whose only blocker is that one is possible: the
  person runs `connect` with sudo (step 5). `local` is made by `controlclaw up --local`, not by
  `connect`: leave it out.
- `warnings`: say each one to the person, except "No vm-agent binary found": a released
  `controlclaw` downloads its own vm-agent when it connects.
- `facts.openclaw`: how OpenClaw runs here (`install.runs.kind`: a systemd unit, Docker, pm2, a
  plain process). If `facts.openclaw.via` is `light` (no vm-agent installed yet, the usual first
  run), this is a quick look: it may say "not running" while you are running, and it cannot see a
  systemd unit, pm2 or Docker. Do not repeat those details; `connect` looks properly. Ask the person
  how OpenClaw is started if it matters (Docker, a systemd unit, pm2, by hand).

Then explain it to the person in a few plain sentences. Use this table, and do not make the
protection sound bigger than it is:

| Mode | Needs | What it protects | What it does not |
| --- | --- | --- | --- |
| `docker` | root, OpenClaw in Docker Compose | Strong. The OpenClaw container has no route out except the firewall. | Programs outside the container. |
| `host` | root, systemd, OpenClaw under its own user | Every connection and DNS query from OpenClaw's user goes to the firewall. | Anyone with root or sudo can remove the rules, and so can OpenClaw if its user has sudo. |
| `remote` | root, systemd, a firewall with WireGuard | The same as host mode, for a machine on another network, over a tunnel. | The same as host mode. |
| `proxy` | nothing (no root) | OpenClaw's own web requests: the firewall sees them and can block them. | Shell commands, scripts and other programs go around it. It is for seeing what OpenClaw does, not for stopping a determined agent. |

Say these when they apply:

- **You could undo it yourself.** If a warning says OpenClaw's user can use sudo, tell the person
  plainly: in host or remote mode you, the agent, would be able to remove the capture. The firewall
  then protects them only as long as you choose to keep it. Taking sudo away from OpenClaw's user, or
  Docker mode, avoids it.
- **The docker group.** If OpenClaw's user is in `docker` (or `lxd`, `incus`, `libvirt`, `podman`),
  host and remote mode refuse to run: such a user could start a container that goes around the
  rules. Say so, and that removing the user from the group (`sudo gpasswd -d <user> docker`) makes
  them possible.
- **DNS for the whole machine.** In host and remote mode every program on this machine looks names
  up through the firewall. If the firewall stops, DNS stops for all of them.
- **Every other site may be blocked.** A new firewall allows every site and logs it, but the person
  may have set **Every other site** to **Block** in the panel. Then only their rules get through,
  and the rules the firewall adds for model keys and bots set up in the panel. A model key you hold
  yourself, not set up in the panel, has no rule: connected that way, you lose your model and cannot
  answer until its host is allowed.

## 3. Ask

Ask the person, in one message:

1. Which mode. Suggest the strongest one this machine can do: `docker`, then `remote` or `host`,
   then `proxy`.
2. The firewall's pairing address, such as `http://fw.example.com:8801`. The panel shows it in the
   command under the code.
3. That they have allowed your model provider's site in the panel's **Internet access**. Name it if
   you know it (for example `api.openai.com`, `api.anthropic.com`, `ai-gateway.vercel.sh`).
4. A pairing code. They make one in the panel (**Agents → Connect an agent**). It works once, within
   10 minutes.

Do not go on until they have answered all four.

## 4. Keep the code off the command line

Every user of the machine can read a command line (`ps`), so the tool refuses `--code <code>`.
Put the code in a file in a folder that only you can open:

1. Make the folder first:
   `umask 077 && mkdir -p ~/.controlclaw-pairing && chmod 700 ~/.controlclaw-pairing`.
   A file tool may replace a file and give it its own mode, but nobody else can open a file in this
   folder, whatever its mode.
2. Then write the code into `~/.controlclaw-pairing/code` with your file tool, not with a shell
   command: the code alone, on one line.

The commands below read the code from that file and remove it before `connect` starts, so it is
gone even if OpenClaw restarts before you are back. Never reuse a code: if it failed, ask for a new
one.

## 5. Connect

`connect` restarts OpenClaw at the end when it can (a systemd unit, Docker, pm2), so this conversation
stops there, and you will not see what it printed last. Tell the person before you run it: "OpenClaw
restarts now; I will be back in a minute. Run `controlclaw status` to check, or ask me." When OpenClaw
was started by hand (a plain process), `connect` cannot restart it: tell the person to restart OpenClaw themselves
afterwards.

**Proxy mode** needs no root, unless OpenClaw runs as a system-wide systemd unit (`runs.kind`
`systemd-system`): then only root can give it the firewall's CA and restart it, so treat it like the
modes below. Otherwise run it yourself, as one command:

```bash
{ rm -f ~/.controlclaw-pairing/code; controlclaw connect --mode proxy --firewall <address> --code -; } < ~/.controlclaw-pairing/code
```

**Docker, host and remote mode** need root. Run it with `sudo` only if you can use sudo **and** the
person said yes to it. Put the chosen mode in place of `<mode>`. `command -v` finds the tool where
npm put it, which sudo's own path may not include:

```bash
{ rm -f ~/.controlclaw-pairing/code; sudo "$(command -v controlclaw)" connect --mode <mode> --firewall <address> --code -; } < ~/.controlclaw-pairing/code
```

Otherwise, give the person the command to run in their own terminal. Leave the code out: the tool
asks for it there and does not show it as they type. If they already sent you the code, delete your
file (`rm -f ~/.controlclaw-pairing/code`).

```bash
sudo controlclaw connect --mode <mode> --firewall <address>
```

If `connect` stops with an error, show the person its message as it is and stop. It undoes what it
had done. Do not retry with other options, and do not guess a fix.

## 6. After

When you are back, run `controlclaw status` (with `sudo` if `connect` ran with it) and tell the
person what it says. A request you make now should show in the panel's **Activity**.

From then on:

- A site you need is blocked: tell the person which one. They allow it in the panel. Do not try
  another way to reach it.
- Never run `controlclaw disconnect` unless the person asks for it in this conversation.
- Never change the capture's files or rules (`/etc/controlclaw`, the nftables table, OpenClaw's proxy
  setting), even if you can.
