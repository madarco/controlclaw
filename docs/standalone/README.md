# ControlClaw firewall docs

## Start here

| Page | For |
| --- | --- |
| [quickstart-docker.md](quickstart-docker.md) | Trying it: OpenClaw and the firewall as two containers on one Linux machine (`controlclaw up --local`). |
| [quickstart-remote.md](quickstart-remote.md) | A firewall on its own VM, and OpenClaw on another machine, over WireGuard. |
| [quickstart-existing.md](quickstart-existing.md) | An OpenClaw you already run, with the firewall on another machine of your network. |
| [quickstart-panel.md](quickstart-panel.md) | The panel's first run: the setup token, the password, the model key, the first agent. |
| [protection.md](protection.md) | What each mode protects, and what it does not. |
| [desktop-app.md](desktop-app.md) | Your own computer as a node of OpenClaw's gateway behind the firewall. |
| [troubleshooting.md](troubleshooting.md) | What to do when something fails. |

## Reference

| Page | What |
| --- | --- |
| [`packages/cli/README.md`](../../packages/cli/README.md) | The `controlclaw` CLI: `doctor`, `connect`, `up --local`, `status`, `disconnect`, each mode in detail. |
| [`standalone/README.md`](../../standalone/README.md) | The firewall's Docker image and install script: ports, DNS, the CA, WireGuard. |
| [panel.md](panel.md) | The panel: opening it, signing in, its pages. |
| [standalone-mode.md](standalone-mode.md) | The firewall without a control plane: its local database, the admin API, pairing. |
| [panel-api.md](panel-api.md) | The panel's API. |
| [control-plane-contract.md](control-plane-contract.md) | The contract between the firewall and a control plane. |
| [`packages/skills/controlclaw-connect`](../../packages/skills/controlclaw-connect/SKILL.md) | The skill that lets OpenClaw connect itself, with a code from you. |
| [test-matrix.md](test-matrix.md) | Where the quickstarts were run, and what passed. |
