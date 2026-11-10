# Quickstart: the firewall next to the OpenClaw you already run

`controlclaw up --here` starts the firewall in a container on the machine where OpenClaw already runs,
and connects that OpenClaw to it. It takes one command, with no pairing code to copy and nothing else
to install. This is the shortest way to add the firewall to an existing OpenClaw.

For a new OpenClaw, use [local Docker](quickstart-docker.md). For a firewall on another machine, see
[the remote quickstart](quickstart-remote.md) or [a firewall on your network](quickstart-existing.md).

You need:

- Linux (amd64 or arm64) with systemd, Node 22 or newer, and Docker 28 or newer with Compose 2.24.4
  or newer. Rootless Docker does not work (see [Limits](#limits)).
- OpenClaw running on that machine, in one of two ways:
  - **In Docker Compose**, for example with OpenClaw's own `docker-compose.yml`. `up` then uses docker
    mode.
  - **Installed on the machine** (with OpenClaw's installer, or npm) and running as its own user, not
    root. `up` then uses host mode.

## 1. Start it

```bash
sudo npx controlclaw up --here      # or: sudo npx controlclaw up, then "Protect the OpenClaw here"
```

It runs two commands, which you can also run yourself:

1. `controlclaw install` pulls the firewall's image for the CLI's version and starts it, in a Compose
   project named `controlclaw-firewall`.
2. `controlclaw connect` runs the same checks as `controlclaw doctor`, finds OpenClaw and how it runs,
   and picks the mode. To choose the mode yourself, add `--mode docker` or `--mode host`. It stops and
   says why when there is no OpenClaw or the mode's checks fail. Otherwise it pairs OpenClaw with the
   firewall with no code, installs the vm-agent and the capture for the mode, and prints its checks.
   Each line should start with ✓.

Then it opens the firewall's panel.

For an OpenClaw in Docker, you can run `npx controlclaw up --here` without sudo if your user can use
Docker (it is in the `docker` group). This only saves the password prompt: anyone in the `docker` group
can do what root does on the machine.

On a machine with a desktop, the panel opens in your browser. Otherwise `up` prints the address, and
the SSH tunnel that reaches it from your computer:

```text
Firewall panel: http://127.0.0.1:8800/#setup=…
  From another machine: ssh -L 8800:127.0.0.1:8800 <this machine>, then open the address above there.
```

Until you set the password, the link carries the panel's one-time setup token, so you don't paste it.
`controlclaw open` shows the link again.

## 2. Set up the panel

Follow [the panel's first run](quickstart-panel.md). OpenClaw is paired already, so skip the pairing
code with **Go to the panel**.

## 3. Check that it works

```bash
sudo npx controlclaw status
```

Every line should start with ✓. Ask OpenClaw something that needs the web. The request shows in the
panel's **Activity**, and your rules decide whether it goes out.

## What changes on the machine

- The firewall's container runs on its own Docker networks, at fixed addresses. Its panel (8800),
  pairing (8801) and pages (8790) are published on this machine's loopback only.
- **Docker mode.** OpenClaw's container moves to the firewall's internal network. The firewall is the
  only other member of that network, and OpenClaw's only way out. The ports OpenClaw published (such
  as its Control UI on 18789) are now published by the firewall's container, on the same addresses.
  Your compose files stay as they are: the CLI adds an override file and names it in the project's
  `.env`.
- **Host mode.** nftables rules send every packet from OpenClaw's user to the firewall's container.
  The whole machine's DNS goes to the firewall too.
- The vm-agent listens on port 3102, and only the firewall's container can reach it. Through it, the
  panel can set OpenClaw's models and bots, and stop OpenClaw.

[protection.md](protection.md) says what each mode protects.

## After a reboot

Docker starts the firewall again, and the capture comes back by itself. You can run `up --here` again
at any time. It starts the firewall if it is not running, runs the checks and opens the panel. It never
pairs twice.

## Limits

- **Rootless Docker** does not work. Its networks live in a namespace of their own, where this machine
  has no address for the vm-agent.
- **Docker mode.** Other services of OpenClaw's Compose project must not run with it. The container
  must not mount Docker's socket, be privileged, or use the host's network. `up` says which one it
  found. MCP servers and app connections do not work in this mode yet.
- **Host mode** needs root, and OpenClaw's user must not be in the `docker` group. If that user can use
  sudo, OpenClaw can remove the rules (`doctor` warns about it).
- Nothing else may listen on this machine's 127.0.0.1:8800, 8801 or 8790, such as another firewall.

## Undo it

```bash
sudo npx controlclaw disconnect                    # OpenClaw back as it was; the firewall stays
sudo npx controlclaw disconnect --restore-config   # also OpenClaw's config as it was before connect
sudo npx controlclaw uninstall                     # disconnect, then the firewall (--purge: its data too)
```

`disconnect` removes the capture and the vm-agent, and makes the firewall forget OpenClaw. What the
panel set in OpenClaw (a model, a bot) stays in OpenClaw's config unless you add `--restore-config`.
`uninstall` also stops and removes the firewall's container. Its data (its Docker volume, with your
rules and the panel's password) stays unless you add `--purge`, and `up --here` picks it up again.

When something fails: [troubleshooting.md](troubleshooting.md).
