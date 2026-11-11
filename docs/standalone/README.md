# ControlClaw firewall docs

Docker mode needs a user in the `docker` group (which can do what root does), or sudo. To add
yourself: `sudo usermod -aG docker $USER`, then log in again. Host and remote mode need sudo.

## Start here

| Page | Read it for |
| --- | --- |
| [quickstart-docker.md](quickstart-docker.md) | A first try: OpenClaw and the firewall as two containers on one Linux machine (`controlclaw up --all`). |
| [quickstart-same-machine.md](quickstart-same-machine.md) | An OpenClaw you already run, with the firewall in a container on the same machine (`controlclaw up --here`). The shortest way for an existing OpenClaw. |
| [quickstart-existing.md](quickstart-existing.md) | One firewall on its own machine in your network (`controlclaw install --listen`), and OpenClaw on other machines (`controlclaw connect`, or `controlclaw openclaw install --firewall`). |
| [quickstart-remote.md](quickstart-remote.md) | A firewall on its own VM, and OpenClaw on another network, over WireGuard. |
| [quickstart-panel.md](quickstart-panel.md) | The panel's first run: the setup token, the password, the model key, the first agent. |
| [protection.md](protection.md) | What each mode protects, and what it does not. |
| [desktop-app.md](desktop-app.md) | Your own computer as a node of OpenClaw's gateway, behind the firewall. |
| [troubleshooting.md](troubleshooting.md) | What to do when something fails. |

## Reference

| Page | What it covers |
| --- | --- |
| [`packages/cli/README.md`](../../packages/cli/README.md) | The `controlclaw` CLI: `up`, `install`, `openclaw install`, `connect`, `open`, `status`, `disconnect`, `uninstall`, `doctor`, and each mode in detail. |
| [`standalone/README.md`](../../standalone/README.md) | The firewall's Docker image and install script: ports, DNS, the CA, WireGuard. |
| [panel.md](panel.md) | The panel: opening it, signing in, its pages. |
| [standalone-mode.md](standalone-mode.md) | The firewall without a control plane: its local database, the admin API, pairing. |
| [panel-api.md](panel-api.md) | The panel's API. |
| [control-plane-contract.md](control-plane-contract.md) | The contract between the firewall and a control plane. |
| [`packages/skills/controlclaw-connect`](../../packages/skills/controlclaw-connect/SKILL.md) | The skill that lets OpenClaw connect itself, with a code from you. |
| [test-matrix.md](test-matrix.md) | Where the quickstarts were run, and what passed. |
