# Quickstart: OpenClaw and the firewall in Docker, on one machine

`controlclaw up --all` starts two containers: the firewall, and a new OpenClaw that can reach the
internet only through the firewall. This is the strongest setup, and the shortest one to try.

You need a Linux machine (amd64 or arm64) with root, Docker 28 or newer with Compose 2.24.4 or newer,
and Node 22 or newer.

## 1. Start it

```bash
sudo npx controlclaw up --all      # or: sudo npx controlclaw up, then "Firewall + new OpenClaw here"
```

`up --local` is the older name of the same command.

It pulls the firewall's image for the CLI's version (`--firewall-image` picks another). The first run
takes a few minutes, while the images download and OpenClaw starts. It prints its checks (each line
starts with ✓), then OpenClaw's address, then opens the firewall's panel. On a machine with no
desktop, it prints the panel's address instead:

```text
OpenClaw: http://127.0.0.1:18789/#token=…
  From another machine: ssh -L 18789:127.0.0.1:18789 <this machine>
Firewall panel: http://127.0.0.1:8800/#setup=…
  From another machine: ssh -L 8800:127.0.0.1:8800 <this machine>, then open the address above there.
Every site is allowed and logged. To lock it down: Internet access, Every other site: Block.
Next: open the panel and set it up.
Undo it with: controlclaw disconnect (the data in /opt/controlclaw-local and the firewall's volume stay)
```

Both addresses work on this machine's loopback only. From your computer, open the SSH tunnels the
output shows. Until you set the panel's password, the panel's link carries the setup token, so you
don't paste it. `controlclaw open` shows the link again.

To do the same in two steps, with OpenClaw in a Compose project of its own:

```bash
sudo npx controlclaw install             # the firewall, in a container
sudo npx controlclaw openclaw install    # a new OpenClaw in Docker, connected to that firewall
```

`openclaw install` connects to the firewall that `install` started, with no code. OpenClaw then runs
in docker mode, which [protects as much](protection.md) as `up --all`.

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
sudo npx controlclaw status
```

Every line should start with ✓. Ask OpenClaw something that needs the web. The request shows in the
firewall's **Activity**. Model calls and bot polling made with a key the firewall put in count as
routine traffic, which **Activity** hides until you turn on **Show routine traffic**.

## Undo it

```bash
sudo npx controlclaw disconnect            # stops both containers; their data stays
sudo npx controlclaw uninstall --purge     # also removes the firewall's volume
```

OpenClaw's data in `/opt/controlclaw-local` stays. Without `--purge`, the firewall's volume stays too,
and running `up --all` again picks both up.

What this setup protects: [protection.md](protection.md). When something fails:
[troubleshooting.md](troubleshooting.md).
