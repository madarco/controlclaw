# Quickstart: OpenClaw and the firewall in Docker, on one machine

`controlclaw up --all` starts two containers: the firewall, and a new OpenClaw that can reach the
internet only through the firewall. This is the strongest setup, and the shortest one to try.

You need a Linux machine (amd64 or arm64) with Docker 28 or newer with Compose 2.24.4 or newer, and
Node 22 or newer. Your user must be in the `docker` group, which can do what root does. To add
yourself, run `sudo usermod -aG docker $USER`, then log in again. Without it, put `sudo` before each
command below.

## 1. Start it

```bash
npx controlclaw up --all      # or: npx controlclaw up, then "Firewall + new OpenClaw here"
```

`up --local` is the older name of the same command.

It runs three commands: `install` (the firewall, Compose project `controlclaw-firewall`),
`openclaw install` (OpenClaw, Compose project `openclaw` in `~/openclaw`, or `/opt/openclaw` with
sudo) and `connect` (docker mode). It pulls the firewall's image for the CLI's version
(`--firewall-image` picks another). The first run takes a few minutes, while the images download and
OpenClaw starts. If it stops half way, run it again: it checks what is there and goes on.

It prints OpenClaw's address, then its checks (each line starts with ✓), then opens the firewall's
panel. On a machine with no desktop, it prints the panel's address instead:

```text
OpenClaw runs in Docker (ghcr.io/openclaw/openclaw:2026.10.9), its files in /home/you/openclaw.
  Control UI: http://127.0.0.1:18789/#token=…
  From another machine: ssh -L 18789:127.0.0.1:18789 <this machine>
…
Connected in docker mode to the firewall on this machine.
Undo it with: controlclaw disconnect (uninstall also removes the firewall)
Firewall panel: http://127.0.0.1:8800/#setup=…
  From another machine: ssh -L 8800:127.0.0.1:8800 <this machine>, then open the address above there.
Every site is allowed and logged. To lock it down: Internet access, Every other site: Block.
Next: open the panel and set it up.
```

Both addresses work on this machine's loopback only. From your computer, open the SSH tunnels the
output shows. Until you set the panel's password, the panel's link carries the setup token, so you
don't paste it. `controlclaw open` shows the link again.

To do the same in two steps:

```bash
npx controlclaw install             # the firewall, in a container
npx controlclaw openclaw install    # a new OpenClaw in Docker, connected to that firewall
```

`openclaw install` connects to the firewall that `install` started, with no code. This is what
`up --all` runs.

## 2. Set up the firewall

Open the firewall's address and follow [the panel's first run](quickstart-panel.md). `up --all`
already paired OpenClaw, so skip the pairing code.

A new firewall allows every site and logs it. To allow only the sites you choose, set **Every other
site** to **Block** under **Internet access**. The model keys and bots you set up in the panel keep
working, because the firewall adds a rule for each.

## 3. Set up OpenClaw

Open OpenClaw's address, with its token. It opens on **Model Setup**: choose your provider and add your
key, as OpenClaw's own docs describe. If you set **Every other site** to **Block** and the panel has no
key for that provider, add a rule for the provider's host in **Internet access**.

## 4. Check that it works

```bash
npx controlclaw status
```

Every line should start with ✓. Ask OpenClaw something that needs the web. The request shows in the
firewall's **Activity**. Model calls and bot polling made with a key the firewall put in count as
routine traffic, which **Activity** hides until you turn on **Show routine traffic**.

## Undo it

```bash
npx controlclaw disconnect            # OpenClaw back on its own network; the firewall stays
npx controlclaw uninstall --purge     # disconnect, then the firewall and its volume
docker compose -p openclaw down       # stops OpenClaw too
```

After `disconnect`, OpenClaw keeps running and reaches the internet directly again. Its data in
`~/openclaw` (or `/opt/openclaw`) stays. Without `--purge`, the firewall's volume stays too.

What this setup protects: [protection.md](protection.md). When something fails:
[troubleshooting.md](troubleshooting.md).
