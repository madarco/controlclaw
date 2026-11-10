# What each mode protects, and what it does not

The firewall can only rule on traffic that reaches it. The **mode** is how OpenClaw's traffic is sent
to it. `controlclaw doctor` says which modes a machine can use. This page says what each one gives
you.

| Mode | How traffic reaches the firewall | Protects | Does not protect |
| --- | --- | --- | --- |
| **Local Docker** (`controlclaw up --all`) | OpenClaw's container is on a network whose only other member is the firewall. | Everything OpenClaw does: its requests, its shell commands, its browser. The firewall is its only route out. | Programs on the machine outside the container. |
| **Docker** (`connect --mode docker`) | Your OpenClaw container moves to such a network. | The same as local Docker. | The same. Also, `connect` refuses a container that could get out on its own (see below). |
| **Same machine, docker mode** (`controlclaw up --here`, OpenClaw in Docker) | Your OpenClaw container moves to the firewall container's internal network. | The same as local Docker. | The same as docker mode. |
| **Same machine, host mode** (`controlclaw up --here`, OpenClaw installed on the machine) | Host mode's rules send everything to the firewall's container on the same machine. | The same as host mode. | The same as host mode. Also, root on the machine can reach the firewall's container and its data (see below). |
| **Remote** (`connect --mode remote`) | A WireGuard tunnel to the firewall, then host mode's rules through it. | The same as host mode, from any network, also behind a NAT. | The same as host mode. |
| **Host** (`connect --mode host`) | nftables rules catch every packet from OpenClaw's user and send it to the firewall. | Everything OpenClaw's user sends: requests, shell commands, DNS. | Anyone with root or sudo can remove the rules. Other users' programs. |
| **Proxy** (`connect --mode proxy`) | OpenClaw's own proxy setting. | OpenClaw's own web requests: the firewall sees them and can block them. | Shell commands, scripts and other programs go around it. The setting is in OpenClaw's own config, which OpenClaw's user can change, so OpenClaw itself (or a prompt that tricks it) can turn it off. |

From strongest to weakest: Docker (local, your own container, or `up --here` in docker mode), then
remote and host (also `up --here` in host mode), then proxy.

## Things to know

**In host and remote mode, root wins.** The rules live in the machine's own nftables, and root, or a
user with sudo, can delete them. If OpenClaw's user can use sudo, OpenClaw itself, or a prompt that
tricks it, can turn the capture off. `doctor` warns when OpenClaw's user is in the `sudo`, `admin` or
`wheel` group. It does not read sudoers, so check `/etc/sudoers` and `/etc/sudoers.d/` yourself for
rules that name the user. Take sudo away from OpenClaw's user, or use Docker mode.

**The docker group is root too.** A user in `docker` (or `lxd`, `incus`, `libvirt`, `podman`) can
start a container. dockerd sends that container's traffic, not the user, so host mode's rules never
see it. Host and remote mode refuse such a user. Remove the user from the group, or use Docker mode.

**Proxy mode is for seeing, not stopping.** OpenClaw's own calls (its model, its web fetches, its
tools that use Node's HTTP) go through the firewall and follow your rules. A shell command such as
`curl` does not. The proxy is also a setting in OpenClaw's own config, which OpenClaw's user can edit.
OpenClaw, or a prompt that tricks it, can turn it off, and `status` then shows it. Use proxy mode on a
machine where you can't use root, or to see what OpenClaw does.

**DNS for the whole machine (host and remote mode).** `connect` points systemd-resolved at the
firewall, and only at it. Every program on the machine then looks up names through the firewall. If
the firewall stops, DNS stops for all of them, not only for OpenClaw.

**A container that could get out is refused (Docker mode).** `connect --mode docker` stops when the
gateway container could leave the internal network another way. It checks for:

- a mounted container runtime socket;
- `privileged`;
- `NET_ADMIN`, `NET_RAW` or `SYS_ADMIN`;
- the host's network.

**One machine for both.** `controlclaw up --all` runs the firewall and OpenClaw as two containers.
OpenClaw's network gives the machine no address, so OpenClaw can't reach the machine's own services
either. `controlclaw up --here` puts the firewall in a container next to the OpenClaw you already run:

- In docker mode it is as strong as local Docker. OpenClaw's container has no way out except the
  firewall's container, and can't reach the machine or the firewall's panel.
- In host mode, root on the machine wins twice. It can remove the rules, **and** it can reach the
  firewall's container and its data (the rules, the panel's password, the CA's key, your keys) with
  `docker exec` or in Docker's volume. Anyone who can use sudo or Docker on the machine can do the
  same. If OpenClaw's user can, so can OpenClaw. A firewall on another machine does not have this
  second problem.
- Running `install` and `connect` without sudo (docker mode, as a user in the `docker` group) saves a
  password prompt, not a risk. The `docker` group can do what root does.

**A new firewall allows every site, and logs it.** Every request is logged in **Activity**. Routine
model calls and bot polling show there only with **Show routine traffic** on. Once the firewall has a
model key, the AI log review reads the log too.

To lock it down, set **Every other site** to **Block** (in **Internet access** or **Security
rules**). Then traffic gets through only by your own rules, or by the rules the firewall adds for what
you set up in the panel: model keys, bots, AgentMail inboxes and Gmail. The panel marks those rules
as added by the firewall. You can't change them, and they go away with the key or the bot.

**Fail closed.** When the firewall is down, captured traffic fails. It does not go out directly. The
rules come back at boot, before the network is up.

**The address is the identity.** The firewall knows each agent by the address its traffic comes from.
That is the container's address, the machine's address on your network, or its WireGuard tunnel
address. Two
machines behind one NAT look like one machine. Give each its own address, or use remote mode.

**The pairing code.** It works once, within 10 minutes, and never crosses the network (only an HMAC
made with it does). `connect` refuses it on the command line, where other users can read it. See
[the CLI's pairing section](../../packages/cli/README.md#pairing).

## What the firewall does with what it sees

Every request shows in the panel's **Activity**, and your rules decide what goes out. The firewall
reads HTTPS by signing a certificate for each site with its own certificate authority (CA). `connect`
makes OpenClaw trust that CA. The CA's private key never leaves the firewall.

More on each mode: [`packages/cli/README.md`](../../packages/cli/README.md#modes).
