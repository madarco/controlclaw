# ControlClaw

ControlClaw is a firewall and control panel for [OpenClaw](https://openclaw.ai): it shows and
controls everything your agent does on the web, in search, in MCP servers and in your apps' APIs.

Every request the agent makes goes through the firewall's proxy, which reads it, logs it and applies
your rules. Your secrets stay on the firewall. You manage it from its own web panel.

## Three ways to run it

| Shape | When | Quickstart |
| --- | --- | --- |
| **Local Docker**: the firewall and OpenClaw as two containers, `controlclaw up --local` | Trying it, or one machine for both. The strongest setup: OpenClaw has no way out but the firewall. | [docs/standalone/quickstart-docker.md](docs/standalone/quickstart-docker.md) |
| **A firewall VM, agents elsewhere**: `install.sh --wireguard`, then `controlclaw connect --mode remote` | OpenClaw on another cloud or at home. | [docs/standalone/quickstart-remote.md](docs/standalone/quickstart-remote.md) |
| **An OpenClaw you already run**: `controlclaw connect --mode docker`, `host` or `proxy` | Keep your install; put the firewall on another machine of your network. | [docs/standalone/quickstart-existing.md](docs/standalone/quickstart-existing.md) |

Then [the panel's first run](docs/standalone/quickstart-panel.md). Before you choose, read
[what each mode protects, and what it does not](docs/standalone/protection.md).

OpenClaw can also connect itself: give it the
[`controlclaw-connect` skill](packages/skills/controlclaw-connect/SKILL.md) and a pairing code. It
asks you before changing anything.

Linux only for now (amd64 and arm64). All the docs: [docs/standalone/](docs/standalone/README.md).
When something fails: [troubleshooting](docs/standalone/troubleshooting.md).

## What is in this repo

- `rust/`: the firewall agent, the proxy (`cc-proxy`), the agent-side vm-agent and the local control
  plane (`cc-local`).
- `standalone/`: the Docker image and the install script for an Ubuntu VM
  ([`standalone/README.md`](standalone/README.md)).
- `packages/cli/`: the `controlclaw` CLI ([`packages/cli/README.md`](packages/cli/README.md)).
- `packages/skills/controlclaw-connect/`: the skill.
- `apps/firewall-panel/`: the firewall's panel, with `packages/fw-api` (its API types) and
  `packages/cc-shell`.
- `packages/console-ui/`: the shared views of the firewall's pages.
- `docs/standalone/`: the docs.

This repo is exported from ControlClaw's own repo, one commit per export.

## Build and test

```bash
./test.sh                          # Rust format, lints and tests, the control-plane cases, the TS packages
rust/scripts/build-box.sh --docker # the static binaries
standalone/docker/build.sh         # the image
```

## Releases

Releases are built and signed in ControlClaw's own repo, not here: they are pinned by its lockfile
and made with its release script. Each release has a `SHA256SUMS` signed with minisign; `install.sh` and the CLI check
it ([`standalone/release/SIGNING.md`](standalone/release/SIGNING.md)).

## Security

See [SECURITY.md](SECURITY.md) to report a problem.

## License

Copyright ControlClaw. Licensed under the GNU Affero General Public License v3.0 only
(`AGPL-3.0-only`, [`LICENSE`](LICENSE)): if you run a changed version for others over a network,
you must offer them its source.
