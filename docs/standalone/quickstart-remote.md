# Quickstart: a firewall VM, and OpenClaw on another network

The firewall runs on its own Ubuntu VM. OpenClaw runs on another machine (in another cloud, or a home
server) and reaches the firewall over WireGuard. The two need no private network between them.

You need:

- **For the firewall:** a fresh Ubuntu 24.04 VM (amd64 or arm64, 2 GB of RAM is enough) with a public
  address. In its cloud firewall, open UDP 51820 and TCP 8801 to the agent's machine.
- **For the agent's machine:** Linux with systemd, sudo, and Node 22 or newer. OpenClaw must be
  installed and running as its own user, not root and not in the `docker` group.

## 1. Install the firewall

On the firewall VM:

```bash
VERSION=0.11.0  # the latest: https://github.com/madarco/controlclaw/releases
curl -fsSLO https://github.com/madarco/controlclaw/releases/download/v$VERSION/controlclaw-install-$VERSION.tar.gz
tar xzf controlclaw-install-$VERSION.tar.gz
sudo ./controlclaw-install-$VERSION/install.sh --version $VERSION --wireguard   # systemd units and WireGuard need root
```

The script checks the release's signature, installs the firewall, and prints what it set up. Its last
line is the fingerprint of the firewall's certificate authority (CA). Keep it, so you can compare it
later.

To check the download itself before you run it, see
[SIGNING.md](../../standalone/release/SIGNING.md#install-without-trusting-the-download).

## 2. Set up the panel

From your computer, open an SSH tunnel to the panel:

```bash
ssh -L 8800:127.0.0.1:8800 root@<firewall address>
```

Open <http://localhost:8800> and follow [the panel's first run](quickstart-panel.md): the setup token,
a password, and the firewall's own model key (optional). Skip the pairing code there with **Go to the
panel**. You make the code in the next step, once the agent's machine is ready.

## 3. Connect the agent's machine

On the agent's machine, install the CLI:

```bash
sudo npm i -g controlclaw     # into the system's Node
sudo controlclaw doctor       # as root, so it can check remote mode
```

`doctor` should show `✓ remote`. In the panel, go to **Agents**, **Connect an agent**, **Make a
pairing code**. The panel shows a command with `--mode host`. For this setup, use `--mode remote`:

```bash
sudo controlclaw connect --mode remote --firewall http://<firewall address>:8801   # WireGuard and nftables need root
```

It asks for the code and does not show it as you type. Then it:

- downloads the vm-agent of its own release and checks its signature;
- pairs with the firewall and gets a tunnel address (`10.77.0.2` for the first agent);
- brings up WireGuard and waits for the firewall's answer;
- installs the capture and the CA, and restarts OpenClaw.

## 4. Check that it works

```bash
sudo controlclaw status       # with sudo, as connect ran
```

Every line should start with ✓. Then ask OpenClaw something that needs the web. The request shows in
the panel's **Activity**, and your rules decide whether it goes out. A new firewall allows every site
and logs it. To allow only the sites you choose, set **Every other site** to **Block** under
**Internet access**.

## Undo it

```bash
sudo controlclaw disconnect                                          # on the agent's machine
sudo ./controlclaw-install-$VERSION/install.sh --uninstall --purge   # on the firewall
```

What this mode protects: [protection.md](protection.md). When something fails:
[troubleshooting.md](troubleshooting.md).
