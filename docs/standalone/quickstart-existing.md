# Quickstart: one firewall on your network for OpenClaw on other machines

You keep OpenClaw where it is. The firewall runs on another machine on the same private network: a
small server or VM at home or in the office, or a VM on your cloud's private network. OpenClaw's
machine then sends its traffic through it.

Other guides may fit better:

- To run the firewall on OpenClaw's own machine, in a container, use
  [`controlclaw up --here`](quickstart-same-machine.md). It is one command.
- For a firewall you reach over the internet (another cloud, no shared network), use
  [the remote quickstart](quickstart-remote.md).
- For a new OpenClaw, the shortest path is [local Docker](quickstart-docker.md).

Pick the mode from what `doctor` says on OpenClaw's machine:

- **docker**, if OpenClaw runs with Docker Compose. This is the strongest.
- **host**, if OpenClaw is installed on the machine (for example with OpenClaw's installer) and runs
  as its own user.
- **proxy**, if you have no root, or only want to see what OpenClaw does.

[protection.md](protection.md) says what each one protects.

You need:

- **For the firewall:** a fresh Ubuntu 24.04 machine (amd64 or arm64, 2 GB of RAM is enough) with an
  address on the private network, such as `192.168.1.20` or `10.0.1.2`. That address must not be
  reachable from the internet.
- **For OpenClaw's machine:** Linux with systemd and Node 22 or newer, on the same network. Docker
  mode needs a user in the `docker` group (which can do what root does) or sudo. Host mode needs
  sudo.

## 1. Install the firewall

On the firewall's machine (it needs Docker 28 or newer and Node 22 or newer), give `--listen` the
machine's private address. This example uses `10.0.1.2`:

```bash
npx controlclaw install --listen 10.0.1.2     # as a user in the docker group, or with sudo
```

The firewall runs in a container. Its proxy (8080), DNS (53), pairing (8801) and gates (3900, 3940)
answer on that address, and its panel stays on the machine's loopback. `install` opens the panel (or
prints its address) and prints a pairing code for the first OpenClaw machine.

If other machines share the network, allow only OpenClaw's machines on those ports. Use your cloud's
firewall for this, because Docker's published ports go around `ufw`.

Without Docker, `sudo npx controlclaw install --host --listen 10.0.1.2` installs the firewall as the
install script's systemd units, which also serve NTP on port 123. It runs the release's `install.sh`.
You can also download and run that script yourself:

```bash
VERSION=0.9.4   # the latest: https://github.com/madarco/controlclaw/releases
curl -fsSLO https://github.com/madarco/controlclaw/releases/download/v$VERSION/controlclaw-install-$VERSION.tar.gz
tar xzf controlclaw-install-$VERSION.tar.gz
sudo ./controlclaw-install-$VERSION/install.sh --version $VERSION --listen 10.0.1.2   # installs systemd units
```

## 2. Set up the panel

From your computer, run `ssh -L 8800:127.0.0.1:8800 <the firewall's machine>`, then open the link
`install` printed. `controlclaw open` on the firewall's machine prints it again. Follow [the panel's
first run](quickstart-panel.md): the setup token, a password, and the firewall's own model key
(optional). Skip the pairing code there with **Go to the panel**.

## 3. Connect OpenClaw

On OpenClaw's machine:

```bash
sudo npm i -g controlclaw   # sudo to install into the system's Node; npx controlclaw works too
controlclaw doctor          # without sudo, it marks the modes that need root as blocked
```

Before the first `connect`, `doctor` can only guess, because it has no vm-agent yet to look with. It may
say OpenClaw is not running, or not in Docker, when it is. `connect` downloads the vm-agent and looks
properly before it changes anything.

Use the code `install` printed, or make one in the panel under **Agents**, **Connect an agent**,
**Make a pairing code**. Then run this. It asks for the code and does not show it as you type:

```bash
controlclaw connect --firewall http://10.0.1.2:8801        # docker mode, as a user in the docker group
sudo controlclaw connect --firewall http://10.0.1.2:8801   # host mode: nftables rules and a system service
```

`--mode auto`, the default, picks docker for an OpenClaw in Docker Compose and host for one installed
on the machine. To choose, add `--mode docker`, `--mode host` or `--mode proxy`. Run proxy mode as
OpenClaw's own user, or with `sudo` when OpenClaw runs as a system-wide service.

`connect` downloads the vm-agent, pairs, installs the CA and the capture, and restarts OpenClaw.

No OpenClaw on that machine yet? `npx controlclaw openclaw install --firewall
http://10.0.1.2:8801` installs one in Docker and connects it in the same run. With `--host` it uses
OpenClaw's own installer, which needs sudo: it installs Node and build tools, and makes a user for
OpenClaw.

With the firewall on another machine, the firewall sees OpenClaw's traffic and applies your rules,
but it cannot call OpenClaw's machine. So Telegram and Slack bots, models, MCP servers, secrets and
web search set in the panel do not reach OpenClaw. The emergency stop blocks OpenClaw's traffic but
does not stop OpenClaw. `connect` tells you this. For those features, use [remote
mode](quickstart-remote.md). Don't give such an agent a bot in the panel: the bot stays there,
waiting for the agent, until you remove it.

You can also let OpenClaw connect itself. Give it the [`controlclaw-connect`
skill](../../packages/skills/controlclaw-connect/SKILL.md), then the address and the code in chat. It
asks you before it changes anything.

## 4. Check that it works

```bash
controlclaw status        # with sudo if you ran connect with sudo
```

Every line should start with ✓. Ask OpenClaw something that needs the web. The request shows in the
panel's **Activity**, and your rules decide whether it goes out.

A new firewall allows every site and logs it. To allow only the sites you choose, set **Every other
site** to **Block** under **Internet access**. The model keys and bots you set up in the panel keep
working, because the firewall adds a rule for each. A model key typed into OpenClaw itself needs a rule
of its own for the provider's host.

## Undo it

```bash
controlclaw disconnect               # on OpenClaw's machine (--restore-config: its config as it was too)
npx controlclaw uninstall --purge    # on the firewall (without --purge its data stays)
```

On each machine, use `sudo` if you set it up with sudo.

When something fails: [troubleshooting.md](troubleshooting.md).
