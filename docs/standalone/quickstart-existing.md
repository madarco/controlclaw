# Quickstart: an OpenClaw you already run

You keep OpenClaw where it is. The firewall goes on another machine on the same private network: a
small server or VM at home or in the office, or a VM on your cloud's private network. OpenClaw's
machine then sends its traffic through it.

For a firewall reached over the internet instead (another cloud, no shared network), use
[the remote quickstart](quickstart-remote.md). For a new OpenClaw, the simplest is
[local Docker](quickstart-docker.md).

The firewall cannot run on OpenClaw's own machine in these modes yet: they both use the same local
port for their agents (3100).

Pick the mode from what `doctor` says on OpenClaw's machine:

- **docker**, if OpenClaw runs with Docker Compose. Strongest.
- **host**, if OpenClaw is installed on the machine (for example with OpenClaw's installer) and runs
  as its own user.
- **proxy**, if you have no root, or only want to see what OpenClaw does.

[protection.md](protection.md) says what each one protects.

You need:

- **the firewall:** a fresh Ubuntu 24.04 machine (amd64 or arm64, 2 GB of RAM is enough) with an
  address on the private network (such as `192.168.1.20` or `10.0.1.2`). That address must not be
  reachable from the internet;
- **OpenClaw's machine:** Linux with systemd and Node 22 or newer, on the same network. Root for
  docker and host mode.

## 1. Install the firewall

On the firewall's machine, with its private address:

```bash
VERSION=0.9.0   # the latest: https://github.com/madarco/controlclaw/releases
curl -fsSLO https://github.com/madarco/controlclaw/releases/download/v$VERSION/controlclaw-install-$VERSION.tar.gz
tar xzf controlclaw-install-$VERSION.tar.gz
sudo ./controlclaw-install-$VERSION/install.sh --version $VERSION --listen <firewall's private address>
```

The proxy (8080), DNS (53) and NTP (123) answer on that address. Pairing (8801) answers on every
address of the machine. If other machines share the network, allow only OpenClaw's machine on 8080,
53 and 123 (with `ufw`, or your cloud's firewall), and close 8801 to the internet. Pairing answers
only a waiting one-time code, but there is no need to leave it open.

## 2. Set up the panel

From your computer, `ssh -L 8800:127.0.0.1:8800 <the firewall's machine>`, then open
<http://localhost:8800>. Follow [the panel's first run](quickstart-panel.md): the setup token, a
password, the firewall's own model key (optional), and allowing your model provider. Skip the
pairing code there (**Go to the panel**).

## 3. Connect OpenClaw

On OpenClaw's machine:

```bash
sudo npm i -g controlclaw
sudo controlclaw doctor     # without sudo, it marks the modes that need root as blocked
```

Before the first `connect`, `doctor` takes only a quick look (it has no vm-agent yet): it may say
OpenClaw is not running, or not in Docker, when it is. `connect` downloads the vm-agent and looks
properly before it changes anything.

In the panel, **Agents → Connect an agent → Make a pairing code**. Then the line for your mode. Each
asks for the code (not shown as you type):

```bash
sudo controlclaw connect --mode docker --firewall http://<firewall's private address>:8801
sudo controlclaw connect --mode host   --firewall http://<firewall's private address>:8801
controlclaw connect --mode proxy --firewall http://<firewall's private address>:8801
```

Run proxy mode as OpenClaw's own user, or with `sudo` when OpenClaw runs as a system-wide service.

`connect` downloads the vm-agent, pairs, installs the CA and the capture, and restarts OpenClaw.

With the firewall on another machine, the firewall sees OpenClaw's traffic and applies your rules,
but it cannot call OpenClaw's machine. So Telegram and Slack bots, models, MCP servers, secrets and
web search set in the panel do not reach OpenClaw, and the emergency stop blocks its traffic but does
not stop it (`connect` says so). For those, use [remote mode](quickstart-remote.md). Do not put a
bot on such an agent in the panel: it stays there, waiting for the agent, until you remove it.

Or let OpenClaw do it: give it the [`controlclaw-connect` skill](../../packages/skills/controlclaw-connect/SKILL.md),
and the address and the code in chat. It asks before it changes anything.

## 4. Check it works

```bash
sudo controlclaw status        # without sudo after a proxy-mode connect without it
```

Every line should start with ✓. Ask OpenClaw something that needs the web: the request shows in the
panel's **Activity**, and a site no rule allows is refused.

## Undo it

```bash
sudo controlclaw disconnect                                          # on OpenClaw's machine
sudo ./controlclaw-install-$VERSION/install.sh --uninstall --purge   # on the firewall
```

When something fails: [troubleshooting.md](troubleshooting.md).
