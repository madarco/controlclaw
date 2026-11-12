<p align="center">
  <img src=".github/assets/hero.png" alt="ControlClaw: the AI firewall for OpenClaw. Open source, AGPL-3.0. AI content rules, AI log review, password swap, human approvals, secrets off the agent, MCP manager, email rules, complete logs. Run it with npx controlclaw up." width="100%">
</p>

# ControlClaw

ControlClaw is an AI firewall and control panel for [OpenClaw](https://openclaw.ai). It filters every
request, including MCP servers and OpenConnector integrations. You can monitor everything, and you
write firewall rules in plain English. Your passwords and API keys stay on the firewall and are swapped
in on the fly.

It can run on a dedicated machine or in a Docker container next to your OpenClaw. Or use our managed
service, [controlclaw.com](https://controlclaw.com), with team chat for many agents, GBrain and daily
backups.

- **AI content rules.** You write rules as sentences, such as "Don't share pay details" or "Ask me
  before pushing anything to GitHub". The firewall's AI checks what agents send and receive against
  them.
- **AI log review.** The AI reads the traffic log and flags requests that look wrong.
- **Password swap.** The agent types a stand-in. The firewall puts in the real password, and only
  on the sites you chose.
- **Human approvals.** Risky actions wait until you approve them.
- **Secrets off the agent.** API keys never reach the agent.
- **MCP manager.** Your MCP servers in one place, with their keys on the firewall.
- **Email rules.** You decide whom the agent can email, and who can email it.
- **Complete logs.** Every request and tool call, live, with the agent that made it.

<p align="center">
  <img src=".github/assets/panel-overview.png" alt="The firewall's panel: requests per minute, blocked requests, response time, the traffic chart and the live requests" width="100%">
</p>

## Three ways to run it

Run `npx controlclaw up` on the machine where the firewall goes. It shows a menu of these ways.

| | How it works | Guide |
| --- | --- | --- |
| **1. A new OpenClaw with its own firewall (strongest)** | `controlclaw up --all` runs the firewall and a new OpenClaw as two containers on one Linux machine, already paired. OpenClaw can reach the internet only through the firewall. | [Local Docker](docs/standalone/quickstart-docker.md) |
| **2. Protect the OpenClaw you already run** | `controlclaw up --here` keeps your install. It starts the firewall in a container next to OpenClaw and connects the two, with no code to copy. | [Same machine](docs/standalone/quickstart-same-machine.md) |
| **3. One firewall for OpenClaw on other machines** | `controlclaw install --listen <private address>` runs the firewall on its own machine in your network. Each OpenClaw machine then runs `controlclaw connect --firewall …` with a one-time code. Over the internet, use WireGuard (remote mode). | [Another machine](docs/standalone/quickstart-existing.md), [Remote firewall](docs/standalone/quickstart-remote.md) |

Next, [set up the panel](docs/standalone/quickstart-panel.md): the password, an optional model key and
your first rule. Before you choose a way, read [what each one protects, and what it does
not](docs/standalone/protection.md).

The firewall runs in Docker on Linux and macOS (amd64 and arm64). OpenClaw's side needs Linux with
systemd for now: `connect`, which `up --all` and `up --here` also run, installs the vm-agent, and it is
built for Linux only. The CLI needs Node 22 or newer.
The containers need Docker 28 or newer with Compose 2.24.4 or newer, and a user in the `docker` group
(which can do what root does) or sudo. To add yourself: `sudo usermod -aG docker $USER`, then log in
again.

## Try it in five minutes

On a Linux machine with Docker, open the menu:

```bash
npx controlclaw up
```

```text
? What do you want to set up?
❯ Firewall + new OpenClaw here  Two containers, OpenClaw's only way out is the firewall. Strongest.
  Protect the OpenClaw here     Keeps your install. The firewall runs next to it.
  Firewall only                 For OpenClaw on other machines. They run `controlclaw connect`.
  New OpenClaw only             Behind a firewall on another machine.
  Connect this OpenClaw         To a firewall on another machine.
```

Choose **Firewall + new OpenClaw here**, which is the same as `up --all`. It starts both containers,
pairs them, prints OpenClaw's address and opens the firewall's panel. On a machine with no desktop it
prints the panel's address instead, with the one-time setup token in the link. The first run takes a
few minutes while the images download and OpenClaw starts.

You can also run the steps one at a time:

```bash
npx controlclaw install             # the firewall, in a container
npx controlclaw openclaw install    # a new OpenClaw in Docker, connected to that firewall
```

`openclaw install` finds the firewall that `install` started and connects to it with no code. If
OpenClaw already runs on the machine, run `controlclaw connect` instead of `openclaw install`.

A new firewall allows every site and logs it. To allow only the sites you choose, set **Every other
site** to **Block** under **Internet access**. The model keys and bots you set up in the panel keep
working, because the firewall adds a rule for each. A model key you type into OpenClaw itself has no
such rule, so add one for its host. Then set up OpenClaw as its own docs describe.

## The commands, and the other ways to do each

`up` runs these commands in order. You can run each one alone, or do the same step another way.

**The firewall: `controlclaw install`.** It runs the firewall in a container on this machine
(`--docker`, the default) or as the install script's systemd units (`--host`, with sudo). Add
`--listen <private address>` to serve OpenClaw on other machines too. Other ways:
[`standalone/docker/compose.yaml`](standalone/docker/compose.yaml) with `docker compose up -d`, or the
release's `install.sh` (`--wireguard` for remote agents). See [`standalone/README.md`](standalone/README.md).

**OpenClaw: `controlclaw openclaw install`.** It installs OpenClaw in Docker (`--docker`, the default,
a Compose project like OpenClaw's own) or with OpenClaw's own installer, as a user of its own
(`--host`, with sudo: the installer installs Node and makes a user). Add `--firewall <url>` to
connect it to a firewall on another machine in the same run.
Other ways: OpenClaw's own installer or `docker-compose.yml`, then `connect`. Ansible support comes
later, because the role needs the control plane.

**The connection: `controlclaw connect`.** It installs the vm-agent and the capture for the mode:
docker, host, proxy or remote (host and remote need sudo). `--mode auto`, the default, picks docker
or host. Without `--firewall`, it pairs with the firewall on this machine, with no code. Another
way: give OpenClaw the [`controlclaw-connect` skill](packages/skills/controlclaw-connect/SKILL.md)
and a pairing code. It asks you before it changes anything.

**Undo.** `controlclaw disconnect` removes the connection. Add `--restore-config` to also put back
OpenClaw's config as it was. `controlclaw uninstall` also removes the firewall, and its data only with
`--purge`. `controlclaw open` opens the panel, and `controlclaw status` checks every part.

Each command in detail: [`packages/cli/README.md`](packages/cli/README.md).

## Two kinds of rules

Site rules say which sites agents may reach: allow, ask you first, or block. Message rules are
sentences that the firewall's AI applies to what agents send and receive on Telegram, Slack, email,
websites, webhooks and apps. A message rule can stop a message, hold it for you, or only record it.
One rule is always on: a password, key or token never leaves.

<p align="center">
  <img src=".github/assets/panel-security-rules.png" alt="Security rules in the panel: four messages rules written as sentences, each with the channels it checks and what it does" width="100%">
</p>

## More docs

[docs/standalone/](docs/standalone/README.md) lists every page. Start with the guides above, then:

- [`packages/cli/README.md`](packages/cli/README.md): the `controlclaw` CLI and each mode in detail.
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

ControlClaw builds and signs releases in its own repo, not here. Each release ships a `SHA256SUMS`
file with a minisign signature, which `install.sh` and the CLI check
([`standalone/release/SIGNING.md`](standalone/release/SIGNING.md)).

## Reporting a security problem

See [SECURITY.md](SECURITY.md) to report a problem.

## License

Copyright ControlClaw. Licensed under the GNU Affero General Public License v3.0 only
(`AGPL-3.0-only`, [`LICENSE`](LICENSE)). If you run a changed version for others over a network, you
must offer them its source.
