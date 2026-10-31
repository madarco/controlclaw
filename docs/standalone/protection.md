# What each mode protects, and what it does not

The firewall can only rule on traffic that reaches it. How OpenClaw's traffic is made to reach it is
the **mode**. `controlclaw doctor` says which modes a machine can do; this page says what you get
from each.

| Mode | How traffic reaches the firewall | Protects | Does not protect |
| --- | --- | --- | --- |
| **Local Docker** (`controlclaw up --local`) | OpenClaw's container is on a network whose only other member is the firewall. | Everything OpenClaw does: its requests, its shell commands, its browser. There is no route out except the firewall. | Programs on the machine outside the container. |
| **Docker** (`connect --mode docker`) | Your OpenClaw container is moved to such a network. | The same as local Docker. | The same. Also, `connect` refuses a container that could get out on its own (see below). |
| **Remote** (`connect --mode remote`) | A WireGuard tunnel to the firewall, then host mode's rules through it. | The same as host mode, from any network, also behind a NAT. | The same as host mode. |
| **Host** (`connect --mode host`) | nftables rules catch every packet from OpenClaw's user and send it to the firewall. | Everything OpenClaw's user sends: requests, shell commands, DNS. | Anyone with root or sudo can remove the rules. Other users' programs. |
| **Proxy** (`connect --mode proxy`) | OpenClaw's own proxy setting. | OpenClaw's own web requests: the firewall sees them and can block them. | Shell commands, scripts and other programs go around it. The setting is in OpenClaw's own config, which OpenClaw's user can change, so OpenClaw itself (or a prompt that tricks it) can turn it off. |

Strongest first: Docker (local or yours), then remote and host, then proxy.

## Things to know

**In host and remote mode, root wins.** The rules are in the machine's own nftables. Root, or a user
with sudo, can delete them. If OpenClaw's user can use sudo, OpenClaw itself, or a prompt that tricks
it, can turn the capture off. `doctor` warns when OpenClaw's user is in the `sudo`, `admin` or `wheel`
group. It does not read sudoers: check `/etc/sudoers` and `/etc/sudoers.d/` yourself for rules that
name the user. Take sudo away from OpenClaw's user, or use Docker mode.

**The docker group is root too.** A user in `docker` (or `lxd`, `incus`, `libvirt`, `podman`) can
start a container whose traffic dockerd sends, not the user, so host mode's rules never see it. Host
and remote mode refuse such a user. Remove it from the group, or use Docker mode.

**Proxy mode is for seeing, not stopping.** OpenClaw's own calls (its model, its web fetches, its
tools that use Node's HTTP) go through the firewall and follow your rules. A shell command such as
`curl` does not. And the proxy is a setting in OpenClaw's own config, which OpenClaw's user can edit:
OpenClaw, or a prompt that tricks it, can turn it off (`status` then shows it). Use it on a machine
where you cannot use root, or to see what OpenClaw does.

**DNS for the whole machine (host and remote mode).** `connect` points systemd-resolved at the
firewall, and only at it. Every program on the machine then looks names up through the firewall. If
the firewall stops, DNS stops for all of them, not only OpenClaw.

**A container that could get out is refused (Docker mode).** `connect --mode docker` stops when the
gateway container mounts a container runtime's socket, is `privileged`, has `NET_ADMIN`, `NET_RAW` or
`SYS_ADMIN`, or uses the host's network. Each of these is a way around the internal network.

**One machine for both.** `controlclaw up --local` runs the firewall and OpenClaw as two containers,
and OpenClaw's network gives the machine no address, so it cannot reach the machine's own services
either. The firewall from `install.sh` and an OpenClaw connected with `connect` cannot share a machine
yet: put the firewall on another machine of your network.

**A new firewall blocks everything.** Until you allow sites in the panel (**Internet access**),
nothing gets out, not even your model provider. Allow your model provider first, then connect.

**Fail closed.** When the firewall is down, captured traffic fails. It does not go out directly. The
rules come back at boot before the network is up.

**The identity is the address.** The firewall knows each agent by the address its traffic comes from:
the container's address, the machine's address on your network, or its WireGuard tunnel address. Two
machines behind one NAT look like one; give each its own address, or use remote mode.

**The pairing code.** It works once, within 10 minutes, and is never sent over the network (only an
HMAC made with it). `connect` refuses it on the command line, where other users can read it. See
[the CLI's pairing section](../../packages/cli/README.md#pairing).

## What the firewall does with what it sees

Every request is in the panel's **Activity**, and your rules decide what goes out. The firewall reads
HTTPS by signing a certificate for each site with its own CA, which `connect` makes OpenClaw trust.
The CA's private key never leaves the firewall.

More on each mode: [`packages/cli/README.md`](../../packages/cli/README.md#modes).
