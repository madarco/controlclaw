# Quickstart: OpenClaw and the firewall in Docker, on one machine

`controlclaw up --local` starts two containers: the firewall, and an OpenClaw whose only way to the
internet is the firewall. This is the strongest setup, and the quickest one to try.

You need a Linux machine (amd64 or arm64) with root, Docker 28 or newer with Compose 2.24.4 or newer,
and Node 22 or newer.

## 1. Start it

```bash
VERSION=0.9.0   # the latest: https://github.com/madarco/controlclaw/releases
sudo npm i -g controlclaw@$VERSION
sudo docker pull ghcr.io/madarco/controlclaw-firewall:$VERSION
sudo controlclaw up --local --firewall-image ghcr.io/madarco/controlclaw-firewall:$VERSION
```

It takes a few minutes the first time (OpenClaw's image, and its first start). It prints its checks
(each line starts with ✓), then where to open things. The first time, also the panel's setup token:

```
OpenClaw:  http://127.0.0.1:18789/#token=…
Firewall:  http://127.0.0.1:8800  (first sign-in: the setup token …)
           From another machine: ssh -L 8800:127.0.0.1:8800 -L 18789:127.0.0.1:18789 <this machine>
! The firewall blocks everything until you add rules in its panel (Internet access): allow your model provider first.
Undo it with: controlclaw disconnect (the data in /opt/controlclaw-local and the firewall's volume stay)
```

Both addresses are on this machine's loopback only. From your computer, open the tunnel the output
shows.

## 2. Set up the firewall

Open the firewall's address and follow [the panel's first run](quickstart-panel.md). `up --local`
already paired OpenClaw, so skip the pairing code. Allow your model provider in **Internet access**.

## 3. Set up OpenClaw

Open OpenClaw's address (with its token). It opens on **Model Setup**: choose your provider and add
your key, as OpenClaw's own docs say. The provider's site must be allowed in the firewall (step 2).

## 4. Check it works

```bash
sudo controlclaw status
```

Ask OpenClaw something that needs the web. The request shows in the firewall's **Activity**, and a
site no rule allows is refused.

## Undo it

```bash
sudo controlclaw disconnect
```

It stops both containers. OpenClaw's data (in `/opt/controlclaw-local`) and the firewall's volume
stay, and `up --local` again picks them up.

What this protects: [protection.md](protection.md). When something fails:
[troubleshooting.md](troubleshooting.md).
