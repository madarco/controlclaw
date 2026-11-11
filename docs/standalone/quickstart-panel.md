# Quickstart: the panel's first run

In the firewall's panel you sign in, connect agents, set the rules and see the traffic. It listens on
the firewall's port 8800, on loopback only. From another machine, open an SSH tunnel first:

```bash
ssh -L 8800:127.0.0.1:8800 <the firewall's machine>
```

Then open <http://localhost:8800>.

## 1. Enter the setup token and choose a password

The panel first asks for a one-time setup token. On the firewall's machine, `controlclaw open` gives
the panel's link with the token in it, and the panel fills it in. For a firewall installed with
`install.sh`, run it with `sudo`, because the token is in the system journal. `up` and `install` show
the same link when they finish.

The token is also in the firewall's log, which writes a new one at each start until there is an
admin:

```bash
sudo journalctl -u controlclaw-mitm-agent | grep 'no admin yet'               # install.sh (the system journal)
docker compose -p controlclaw-firewall logs firewall | grep 'no admin yet'    # install, up --here, up --all
```

Only the newest token works.

Paste the token if the panel did not fill it in, then choose the admin password (12 characters or
more). The password signs you in for 12 hours.

## 2. Add an AI model key (optional)

This key is for the firewall itself, which uses it to review what agents send. It is not OpenClaw's
model key. Skip it if you don't want the AI review. You can add one later in **Settings**.

## 3. Connect your first agent (optional)

**Make a pairing code** gives a one-time code and the command to run on the agent's machine. The
command says `--mode host`. Change it to the mode you chose ([protection.md](protection.md)). The code
works once, within 10 minutes, and the panel does not show it again.

Skip this step with **Go to the panel** when:

- you ran `up` or `connect` on the firewall's machine, which pair OpenClaw by themselves;
- you want to make the code later, in **Agents**.

You can also let OpenClaw connect itself. Give it the
[`controlclaw-connect` skill](../../packages/skills/controlclaw-connect/SKILL.md) and the code in
chat. It runs `doctor`, explains what the firewall will protect, and asks you before it connects.

## 4. Decide what the agent may reach

A new firewall allows every site and logs it. To allow only the sites you choose, open **Internet
access** and set **Every other site** to **Block**. The change applies at once.

The model keys in **Settings** and the bots in **Channels** keep working after that. The firewall adds
a rule for each, such as `api.anthropic.com` for an Anthropic key or `api.telegram.org` for a
Telegram bot's agent. The rule says what added it, and goes away with the key or the bot. You can't
change those rules. Add your own rules for anything else the agent needs, such as the host of a model
key you typed into OpenClaw itself.

## 5. See the traffic

**Overview** and **Activity** show each request, the agent that made it, and whether the firewall let
it through. **Activity** hides routine traffic (model calls and bot polling made with a key the
firewall put in) until you turn on **Show routine traffic**. The Overview still counts it. **Agents**
lists the paired agents with their traffic.

More on the panel: [panel.md](panel.md).
