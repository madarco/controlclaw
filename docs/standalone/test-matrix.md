# Test matrix

Where the quickstarts were run, from the docs only, and what passed. The newest run is first.

## The release under test

No release was published yet, so each run used a signed release built the same way a real one is:
`CC_RELEASE_DRY_RUN=1 standalone/release/release.sh <version>`. Both architectures are built twice
and compared, then signed with a throwaway key (`CC_RELEASE_PUBKEY_FILE`); the CLI and `install.sh`
carry that key.

Every command was copied from the doc. Only where the files come from changed:

| The doc says | The run used |
| --- | --- |
| `https://github.com/madarco/controlclaw/releases/download/v$VERSION/…` | the release folder served over HTTP, reached from each server through an SSH tunnel (`http://127.0.0.1:8000/v$VERSION/…`) |
| `install.sh --version $VERSION` | `CC_RELEASE_URL=http://127.0.0.1:8000/v$VERSION` in front of it |
| `npm i -g controlclaw` | `--registry http://127.0.0.1:4873` (a Verdaccio holding the release's `controlclaw-<version>.tgz`) |
| `controlclaw connect` / `up --local` downloading the vm-agent | `CONTROLCLAW_RELEASE_URL=http://127.0.0.1:8000/v{version}` in front of it (for the skill: in OpenClaw's service environment) |
| `ghcr.io/madarco/controlclaw-firewall:$VERSION` | `localhost:5000/controlclaw-firewall:$VERSION` (the release's OCI archive copied into a local registry with `skopeo copy --all`) |

The signature checks ran as in a real install: `install.sh` and the CLI checked `SHA256SUMS.minisig`
against the key they carry.

## Fixes checked after the second run (0.9.3, 2026-10-31)

Three of the second run's bugs were fixed on `standalone/matrix-fixes` and checked on fresh Hetzner
cx23 servers (x86, Ubuntu 24.04), with a dry-run release 0.9.3 served as above. OpenClaw was
2026.10.9, the model Claude Haiku 5.5 through Vercel's AI Gateway, the bot Telegram test bot E.

| Bug | Shape | What was checked |
| --- | --- | --- |
| Restart loop | Remote, x86 pair, OpenClaw as a systemd user unit, Telegram on | A long turn running, then three secret changes 10 s apart. OpenClaw drained for about 50 s (systemd `deactivating`, the gateway still answering). One `openclaw gateway restart` ran; the other two pushes joined it, each answered 200 within 20 s, and none was sent again. OpenClaw was back after about 75 s with Telegram polling and all three secrets in its `.env`. |
| Model from the firewall | Remote, and `up --local` | `POST /api/llm/agents/{vmId}` with `anthropic/claude-haiku-5.5` on the AI Gateway: OpenClaw got `models.providers.vercel-ai-gateway` (OpenAI-compatible) and the primary `vercel-ai-gateway/anthropic/claude-haiku-5.5`. The call took 31 to 32 s and answered 200; a turn answered through the firewall. |
| MCP on `up --local` | `up --local`, x86 | DeepWiki listed, a call held and approved in **Permission requests**, then answered. OpenClaw's web fetch still goes through the proxy: an allowed site answered, a blocked one got 403 `blocked_by_policy`. The gates' relay still answered after `docker restart` of OpenClaw. |

The relay that fixes MCP on `up --local` was first a sidecar container on OpenClaw's network: after
a restart of OpenClaw it was left on a network that no longer existed, so it now runs inside
OpenClaw's container. That last version was checked with its Compose file and relay written by the
branch's CLI code onto the 0.9.3 install, not from a new release build.

## Results, 2026-10-31 (second run, before the first release)

- Release 0.9.1, built from `feature/standalone` at `383311e0a`, after #705 and #706.
- The image is `controlclaw-firewall:0.9.1`, manifest list `sha256:4f305d24fffa…`.
- OpenClaw was 2026.10.9: from npm on the agent, and the image `ghcr.io/openclaw/openclaw:2026.10.9`
  for Docker Compose and `up --local`.
- The model went through Vercel's AI Gateway (Claude Haiku 5.5).
- Servers were Hetzner cx23 (x86, 4 GB) and cax11 (arm, 4 GB), Ubuntu 24.04.4, Docker 29.9, made
  fresh for this run and deleted after. Local Docker ran on a Linux x86 box (Docker 29.1, Compose
  2.40).

| Quickstart | Docker on Linux (x86) | Hetzner x86 pair | Hetzner arm |
| --- | --- | --- | --- |
| [Local Docker](quickstart-docker.md) | ✓ | n/a (one machine) | ✓ (`up --local` on the arm server) |
| [Remote VM pair](quickstart-remote.md) | n/a | ✓ | ✓ (arm firewall, x86 agent) |
| [Existing OpenClaw](quickstart-existing.md) (firewall on the same private network) | n/a | ✓ host, ✓ proxy | ✓ docker (OpenClaw in Docker Compose on arm, x86 firewall) |
| [Panel first run](quickstart-panel.md) | ✓ | ✓ | ✓ |
| [The connect skill](../../packages/skills/controlclaw-connect/SKILL.md) | | proxy: ✓ the second attempt, ✗ the first (the code in a shell command, see bugs); remote: not run | |

The Mac shapes are skipped for the first release:

| Shape | Result |
| --- | --- |
| Docker Desktop on an Apple-silicon Mac ([quickstart-docker.md](quickstart-docker.md)) | skipped for the first release |
| Mac, proxy only | skipped for the first release (the CLI is Linux only; `doctor` says so on macOS) |

What "✓" checked:

- the command's own checks (`connect`, `up --local`), and `status` again after;
- `doctor` before and after (`connect` shapes);
- requests from OpenClaw's user: an allowed host answered, a host no rule allows got 403
  `blocked_by_policy`, and a direct IP got 403;
- a real OpenClaw turn on each connect and `up --local` shape: the model answered through the firewall, and its web fetch of a blocked site
  was refused;
- the request in the panel's **Activity**, with the agent's name;
- `disconnect`: no nft table, the DNS back, no tunnel, no vm-agent.

What the firewall sets on an agent (#705, #706), where the docs say it works:

| Feature | `up --local` (x86 box) | Remote, x86 firewall | Remote, arm firewall | `up --local` (arm) | Host, proxy, docker across a network |
| --- | --- | --- | --- | --- | --- |
| Telegram bot (Bot D): added in **Channels**, a person approved with the bot's code, a message answered | ✓ | ✓ (the agent has a stand-in, not the token) | not run | not run | does not reach OpenClaw, as the doc says; the panel still keeps the bot (see bugs) |
| Model from the firewall (`POST /api/llm/agents/{vmId}`, no panel page) | | ✗ see bugs | | | n/a |
| MCP server (`mcp.deepwiki.com`, no auth): pushed to OpenClaw at the gate | ✗ see bugs | ✓ after the call was approved in **Permission requests** | ✓ pushed and removed | | n/a |
| Secret: placeholder in OpenClaw's `.env`, the real value only to its host | | ✓ (`httpbin.org` saw the value) | | ✓ (in the container) | n/a |
| Web search key | | ✗ the push fails (see bugs); live search not run: no test key | | | n/a |
| Emergency stop: **Stop**, then **Start again** | | ✓ OpenClaw stopped, traffic 403, back after | ✓ | ✓ (the container stopped and came back) | traffic 403; OpenClaw not stopped, as the doc says |
| NTP on the tunnel address | | ✓ (answers on 10.77.0.1, not on the public address) | | | n/a |

The connect skill, with OpenClaw on Haiku 5.5:
- **proxy mode:** OpenClaw wrote the code to its 0600 file and ran `connect` itself. The file was gone
  after the restart, and OpenClaw checked `status` when asked.
- **The ps watch:** a `ps` watch during the run saw the code only in the test's own
  `openclaw agent --message` command.
- **An earlier attempt:** OpenClaw wrote the code with `printf` in a shell command (visible in `ps`)
  instead of its file tool, then stopped on the vm-agent download.

## Results, 2026-10-31 (first run)

- Release 0.9.0, before #705 and #706, with the same servers and OpenClaw.
- Every quickstart passed:
  - local Docker on Linux x86 and on arm;
  - the remote pair, x86 and with an arm firewall;
  - existing OpenClaw on the x86 pair (host, proxy and docker);
  - the panel's first run on each;
  - the connect skill, in remote mode (the owner ran the command OpenClaw gave) and in proxy mode.

## Fixed in the docs by the runs

Second run:
- The existing-OpenClaw page says that with the firewall on another machine, bots, models, MCP
  servers, secrets and search do not reach OpenClaw, and the emergency stop only blocks its traffic:
  use remote mode for those.
- The panel's first run says that a Telegram bot needs `api.telegram.org` allowed. Adding the bot does
  not allow it, so OpenClaw's calls to Telegram were blocked.

First run:
- **The existing-OpenClaw page** first had the firewall on OpenClaw's own machine. That does not work
  yet:
  - pairing refuses loopback;
  - the `docker0` address is masqueraded to the public one;
  - the firewall agent and the vm-agent both listen on 127.0.0.1:3100.

  The page now puts the firewall on another machine of the same network.
- **`doctor`** before the first `connect` did not see OpenClaw in Docker. The page now says that
  `connect` looks properly.
- **The pairing command.** The panel's button is **Make a pairing code**, and the command it shows
  always says `--mode host`. The remote and panel pages now say which mode to use instead.
- **`status`** lines start with ✓, not "ok".
- **The panel's model key** is the firewall's own (its AI review), not OpenClaw's. The panel page says
  so, and the Docker page sends OpenClaw's key to its **Model Setup**.
- **The skill:**
  - `doctor` run without root marks the root modes as blocked, so OpenClaw offered only proxy mode.
    The skill now treats "needs root" as "the owner runs it with sudo".
  - The code file was left behind when `connect` restarted OpenClaw mid-command. The command now
    removes it before `connect` starts.

## Bugs found by the second run

The restart loop, the model from the firewall and MCP on `up --local` are fixed (above). The
others are open.

Each has a line in [the backlog](../plans/standalone-backlog.md#found-along-the-way).

- **Restart loop (vm-agent, high).**
  - A change that restarts OpenClaw (a secret, removing a Telegram bot) while its Telegram channel
    is on: OpenClaw 2026.10.9 then takes up to its 330 s stop timeout to stop.
  - The vm-agent logs "config write landed while the gateway was restarting; sending it again once
    it is back". It then ran `openclaw gateway restart` every ~35 s, so OpenClaw never finished
    starting.
  - It stopped only when the vm-agent was stopped.
  - Pushes during this answered `agent 500: }` or "The agent is not running".
- **Model from the firewall.**
  - `POST /api/llm/agents/{vmId}` with Vercel AI Gateway left OpenClaw on
    `anthropic/claude-haiku-5.5` with no key, so its turns failed.
  - Stock OpenClaw has no `vercel-ai-gateway` provider.
  - The call answered "The agent did not answer in time", while the vm-agent was still running its
    CLI calls (`config patch`, `models auth paste-api-key`, about 13 s each).
  - The panel has no page for it.
- **MCP on `up --local`.** OpenClaw's MCP client sends the gate request (`172.31.251.2:3940`) through
  `HTTPS_PROXY`, and the proxy refuses it as `non_routable_target`. So the server never starts there.
- **The connect skill.** On its first attempt, OpenClaw (Haiku 5.5) wrote the pairing code with
  `printf` in a shell command, where `ps` showed it to every user on the machine, instead of using
  its file tool. The second attempt followed the skill.
- **MCP approvals.**
  - The gate's "needs approval" answer has no `structuredContent`. For a tool with an
    `outputSchema`, OpenClaw rejects it as a schema error, and the agent never sees that it waits for
    a person.
  - The answer names `cc-perm`, which an unmanaged agent does not have.
  - The request shows "firewall" as the agent, with empty host, method and path.
  - A server with no annotations (DeepWiki) counts as destructive, so every call waits for approval.
- **MCP calls are not in Activity.** Tools and Integrations show 0 after approved calls.
- **Search push.** On stock OpenClaw the push answers `agent 500: }` or "not running", not which
  plugin is missing. `openclaw plugins install @openclaw/tavily-plugin` installed nothing.
- **A bot on an agent the firewall cannot reach** (host mode across a network):
  - the add answers 409, but the bot stays on that agent;
  - its card says "Applied, waiting for the agent to report" forever;
  - **Remove from agent** and the stop say "This firewall does not know that agent" instead of "cannot
    reach it";
  - only `DELETE …?force=true` removes the bot.
- **`disconnect` leaves the firewall's settings in OpenClaw.** The Telegram stand-in, the MCP server
  at the old gate address and the secret's placeholder in `.env` stay, while it says "as it was before
  connect".
- **Secrets have no panel page and no doc.** They work only through
  `POST /api/commands {action: "secrets.propose"}`, with an `agents[].hostname` (the agent's address,
  without the port) written by hand.
- **Minor:**
  - "That does not look like a OpenAI API key";
  - before the first `connect`, `doctor` warns "connect needs one (--vm-agent <path>)", but `connect`
    downloads it;
  - with no OpenClaw found, `doctor` still warns "OpenClaw runs as root";
  - the New rule dialog says "All boxes";
  - a working bot's card still says "Applied, waiting for the agent to report".
