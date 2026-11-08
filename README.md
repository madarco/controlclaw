<p align="center">
  <img src=".github/assets/hero.png" alt="ControlClaw: the AI firewall for OpenClaw. AI content rules, AI log review, password swap, human approvals, secrets off the agent, MCP manager, email rules, complete logs. Three ways to run it." width="100%">
</p>

# ControlClaw

ControlClaw is an AI firewall and control panel for [OpenClaw](https://openclaw.ai). Every request
your agent makes goes through it. You see each one, your rules decide what goes out, and your
passwords and API keys stay on the firewall.

It runs on your own machine, with its own web panel. No account, no cloud.

- **AI content rules.** Rules in plain sentences, checked by AI. "Don't share pay details." "Ask me
  before pushing anything to GitHub." The firewall's AI reads what agents send and receive.
- **AI log review.** The AI reads the traffic log and flags odd traffic.
- **Password swap.** The agent types a stand-in. The firewall puts in the real password, only on the
  sites you chose.
- **Human approvals.** Risky actions wait for your OK.
- **Secrets off the agent.** API keys never reach the agent.
- **MCP manager.** MCP servers in one place, keys on the firewall.
- **Email rules.** Who the agent can email, and who can email it.
- **Complete logs.** Every request and tool call logged, live, with the agent that made it.

<p align="center">
  <img src=".github/assets/panel-overview.png" alt="The firewall's panel: requests per minute, blocked requests, response time, the traffic chart and the live requests" width="100%">
</p>

## Three ways to run it

| | How | Guide |
| --- | --- | --- |
| **1. Add it to the OpenClaw you run** | Keep your install. The firewall goes on a small server or VM on your network, and OpenClaw's machine sends its traffic through it. Run `controlclaw connect --mode docker`, `host` or `proxy`. | [Existing OpenClaw](docs/standalone/quickstart-existing.md) |
| **2. A firewall on its own machine** | OpenClaw anywhere (another cloud, a home server), the firewall on its own VM. The agent reaches it over WireGuard and cannot read the firewall's data. Everything you set in the panel reaches OpenClaw: bots, models, MCP servers, secrets, the emergency stop. Install with `install.sh --wireguard`, then run `controlclaw connect --mode remote`. | [Remote firewall](docs/standalone/quickstart-remote.md) |
| **3. Start fresh (recommended)** | The firewall and a new OpenClaw as two containers on one Linux machine, paired already. OpenClaw's only way out is the firewall. Run `controlclaw up --local`. | [Local Docker](docs/standalone/quickstart-docker.md) |

Then [set up the panel](docs/standalone/quickstart-panel.md): the setup token, a password, and the
first rule. Before you choose, read [what each way protects, and what it does not](docs/standalone/protection.md).

OpenClaw can also connect itself. Give it the
[`controlclaw-connect` skill](packages/skills/controlclaw-connect/SKILL.md) and a pairing code. It
asks you before it changes anything.

Linux only for now (amd64 and arm64).

## Try it in five minutes

On a Linux machine with Docker 28 or newer and Node 22 or newer:

```bash
VERSION=0.9.4   # the latest: https://github.com/madarco/controlclaw/releases
sudo npm i -g controlclaw@$VERSION
sudo docker pull ghcr.io/madarco/controlclaw-firewall:$VERSION
sudo controlclaw up --local --firewall-image ghcr.io/madarco/controlclaw-firewall:$VERSION
```

It prints the panel's address and its one-time setup token, and OpenClaw's address. A new firewall
blocks everything: open the panel, allow your model provider under **Internet access**, then set up
OpenClaw as its own docs say.

## Two kinds of rules

Site rules say which sites agents may reach: allow, ask you first, or block. Messages rules are
sentences the firewall's AI applies to what agents send and receive, on Telegram, Slack, email,
websites, webhooks and apps. A rule can stop a message, hold it for you, or only record it. One rule
is always on: a password, key or token never leaves.

<p align="center">
  <img src=".github/assets/panel-security-rules.png" alt="Security rules in the panel: four messages rules written as sentences, each with the channels it checks and what it does" width="100%">
</p>

## More docs

[docs/standalone/](docs/standalone/README.md) has every page. Start with the quickstarts above, then:

- [`packages/cli/README.md`](packages/cli/README.md): the `controlclaw` CLI, each mode in detail.
- [`standalone/README.md`](standalone/README.md): the firewall's Docker image and install script, its ports, DNS and the CA.
- [Your own computer behind the firewall](docs/standalone/desktop-app.md), as a node of OpenClaw's gateway.
- [Troubleshooting](docs/standalone/troubleshooting.md), when something fails.

## What is in this repo

- `rust/`: the firewall agent, the proxy (`cc-proxy`), the agent-side vm-agent and the local control
  plane (`cc-local`).
- `standalone/`: the Docker image and the install script for an Ubuntu VM.
- `packages/cli/`: the `controlclaw` CLI.
- `packages/skills/controlclaw-connect/`: the skill that lets OpenClaw connect itself.
- `apps/firewall-panel/`: the panel, with `packages/fw-api` (its API types) and `packages/cc-shell`.
- `packages/console-ui/`: the panel's views.
- `docs/standalone/`: the docs.

ControlClaw exports this repo from its own repo, one commit per export.

## Build and test

```bash
./test.sh                          # Rust format, lints and tests, the control-plane cases, the TS packages
rust/scripts/build-box.sh --docker # the static binaries
standalone/docker/build.sh         # the image
```

## Signed releases

ControlClaw builds and signs releases in its own repo, not here. Each one ships a `SHA256SUMS` with a
minisign signature, which `install.sh` and the CLI check
([`standalone/release/SIGNING.md`](standalone/release/SIGNING.md)).

## Reporting a security problem

See [SECURITY.md](SECURITY.md) to report a problem.

## License

Copyright ControlClaw. Licensed under the GNU Affero General Public License v3.0 only
(`AGPL-3.0-only`, [`LICENSE`](LICENSE)): if you run a changed version for others over a network,
you must offer them its source.
