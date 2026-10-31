# Quickstart: the panel's first run

The firewall's panel is where you sign in, connect agents, set the rules and see the traffic. It is
on the firewall's port 8800, on loopback only. From another machine, open an SSH tunnel first:

```bash
ssh -L 8800:127.0.0.1:8800 <the firewall's machine>
```

Then open <http://localhost:8800>.

## 1. The setup token and the password

The panel first asks for a one-time setup token. The firewall writes it to its log at each start,
until there is an admin:

```bash
sudo journalctl -u controlclaw-mitm-agent | grep 'no admin yet'      # installed with install.sh
sudo docker compose -p controlclaw-local logs firewall | grep 'no admin yet'   # up --local
```

Only the newest token works. `up --local` also prints it.

Paste it, then choose the admin password (12 characters or more). The password signs you in for 12
hours.

## 2. An AI model key (optional)

This key is for the firewall itself: it uses it for its AI review of what agents send. It is not
OpenClaw's model key. Skip it if you do not want the AI review; you can add one later in
**Settings**.

## 3. The first agent (optional)

**Make a pairing code** gives a one-time code and the command to run on the agent's machine. The
command says `--mode host`: change it to the mode you chose ([protection.md](protection.md)). The code
works once, within 10 minutes, and is not shown again. Skip this step with **Go to the panel**: for
`up --local`, which pairs OpenClaw itself, or to make the code later in **Agents**.

You can also let OpenClaw connect itself: give it the
[`controlclaw-connect` skill](../../packages/skills/controlclaw-connect/SKILL.md) and the code in
chat. It runs `doctor`, explains what the firewall will protect, and asks you before it connects.

## 4. Allow what the agent needs

A new firewall blocks every request. Before the agent can do anything, open **Internet access** and
add an allow rule for your model provider, for example `api.openai.com` or `api.anthropic.com`. A
change applies at once.

A Telegram bot (**Channels**) needs `api.telegram.org` allowed too: adding the bot does not allow it,
and until then OpenClaw cannot reach Telegram.

## 5. See the traffic

**Overview** and **Activity** show each request, the agent that made it, and whether it was allowed.
**Agents** lists the paired agents with their traffic.

More on the panel: [panel.md](panel.md).
