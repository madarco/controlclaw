# The local panel

A standalone firewall has its own web panel (`apps/firewall-panel`), served by the firewall itself
on the same address as its API: `LOCAL_PANEL_BIND`, `127.0.0.1:8800` by default. It talks only to
that API ([`panel-api.md`](panel-api.md)) and draws the console's own screens from
`packages/console-ui`.

## Opening it

- **On the firewall's machine**: `http://localhost:8800`.
- **On a server**: an SSH tunnel, `ssh -L 8800:127.0.0.1:8800 <server>`, then `http://localhost:8800`.
- **Docker**: `compose.yaml` publishes 8800 on the host's loopback. Inside the container the panel
  listens on every address (`LOCAL_PANEL_BIND=0.0.0.0:8800` with `LOCAL_PANEL_INSECURE=1`, set in
  `compose.yaml`), since the host cannot reach the container's loopback. The compose project's own
  network keeps containers on other networks (agents on Docker's default bridge) from reaching it. Do
  not attach agent containers to that network, and do not set these two with `docker run` on the
  default bridge: an agent that reaches the API could use up the sign-in tries and keep you out.
- **HTTPS with your own name** (Caddy, Tailscale Serve): proxy the name to `127.0.0.1:8800` and add
  it to `LOCAL_PANEL_HOSTS`. Another name gets 421, page and API alike.

## First run

1. The firewall logs a one-time setup token at each start while there is no admin:
   `[cc-local] no admin yet: set the password with this one-time setup token …`. Only the newest
   line works. Read it with `journalctl -u controlclaw-mitm-agent` (install script) or
   `docker compose logs firewall` (Docker).
2. The panel asks for the token and the admin password (12 characters or more).
3. An AI model key, optional: the firewall's AI review runs only with one of your own keys.
4. The first agent, optional: the panel makes a one-time pairing code and shows the command to run on
   the agent's machine (`controlclaw connect`, [`packages/cli/README.md`](../../packages/cli/README.md#pairing)).
   The code works once, within 10 minutes, and is not shown again.

## Signing in

- The password signs in for 12 hours (the session cookie). **Sign out** ends every session.
- When the firewall ends the session (it expired, or someone signed out elsewhere), the next call
  answers 401 and the panel shows "You were signed out", then goes on where it was after signing in.
- Ten tries a minute from one address, thirty in all, then "Too many tries. Wait a minute." Behind an
  SSH tunnel every browser shares one address.

## Changing the password

- **Settings → Admin password**: the current password, then the new one twice (12 characters or more).
  The current one is checked like a login and counts toward the same ten tries a minute.
- The change signs out every other browser. The one that made it stays signed in.

## Forgot the password

Run this on the firewall's machine, as the firewall's user:

- Install script: `sudo -u controlclaw mitm-agent reset-admin`
- Docker: `docker exec -u controlclaw <container> mitm-agent reset-admin`

It removes the admin password, ends every session and prints a new one-time setup token. The panel
then shows the first-run page again: type the token and a new password. The firewall does not need a
restart, and nothing else changes (rules, keys and agents stay). Anyone with root on the machine can
do this, the same as reading the log's setup token.

## Pages

| Page | Today |
| --- | --- |
| Overview | the console's Overview: requests per minute, blocked, response time, this month, the traffic chart, live requests, AI findings, top hosts and traffic per agent. Not here: Most used rules and the rules section (the firewall keeps no per-rule counts) and Protected services. |
| Agents | the paired agents with their last 24 hours of traffic, and pairing codes (make, list, revoke) |
| Internet access | your own exit proxy (the Exit card: connect, settings, check, remove), the site rules (add, edit, cycle, delete; a change applies at once), then the AI Firewall and AI Log Review. AI Log Review has no Notify (no one to email; findings are in Activity) and no review history. |
| Security rules | Messages (content rules, with Try a message), Email, Websites, Integrations (app and MCP rules) and Settings (the AI cards). No Auto approve tab (no such rules here). Email shows how to add a mailbox until AgentMail and Google come to the panel. App rules offer no action picker (the console's action catalog is not on the firewall). |
| Channels | Telegram and Slack bots, one agent at a time: add, replace the token, put on or take off an agent. A person is approved with the pairing code the bot sent them and their id on the channel (the firewall lists no waiting people). No WhatsApp yet. |
| Integrations | (needs `CONNECTOR_GATE_BIND`, the address agents reach the firewall's gates at; without it the firewall runs no connectors or MCP servers and the page says so) connected apps (the pinned OpenConnector catalog, searched in the panel; API key, credential and OAuth apps) and MCP servers. An OAuth sign-in opens the provider in a new tab, which comes back to `/oauth/callback`; that page hands the answer to the firewall and tells the first tab. |
| Permission requests | what agents asked, waiting first; Approve or Deny. No "Always allow" (that is the console's auto approve rules). |
| Activity | Network, Tools, Runs, Findings and Integrations, with the verdict counts, a search and pages of 50 |
| Settings | AI model keys (add, replace, remove) |
| Website logins | the logins the firewall types in (name, sites, agents, whether it is swapped into the request or typed into the page), never a password; edit and delete; 1Password's read and disconnect. **Add a login** opens the firewall's own Logins page in a new tab (a one-time link), where the password is typed. |
| Google (Integrations → Google) | your own OAuth client: the redirect address to register (and, when Google would refuse it, why: Google takes only https or http on localhost; open the panel through an SSH tunnel, or set `LOCAL_PANEL_URL`), the client's JSON, the services and scopes, Sign in with Google in a new tab, then the services (turning one off at once; one Google was not asked for needs Connect again) and the agents (with Send again). No Drive folders and no Gmail push yet. |
| AgentMail (Integrations → AgentMail) | a new account (AgentMail emails a code to claim it) or an existing key; inboxes per agent (create, give, send again, take off, delete with the address typed). Only paired agents get an inbox: it is set up at the address pairing gave them. Who may email an inbox is in Security rules → Email. |

A page whose API the firewall does not have says "Coming soon"; so does the admin password change in
Settings.

**Stop** in the header stops every agent (no model calls, no web, no channels) after you type STOP;
a red line across the top says so until **Start again**.

While `panel.js` loads, `panel.html` shows a plain "Loading the firewall panel…" line (inline CSS, no
script, in the theme's colours by `prefers-color-scheme`).

## How it is built and served

- The firewall's own pages (Logs, Doctor start, and the stylesheet every page links) are built by
  `scripts/build-fw-files.mjs` from this app and `packages/console-ui`, so the public repo builds
  them too (`pnpm --filter @controlclaw/firewall-panel build:fw`; `rust/scripts/build-ui.sh` runs
  it). It scans the Rust agent's page sources for their classes.
- Vite builds three flat files with fixed names: `panel.html`, `panel.js` and `panel.css` (the Inter
  font inlined). `rust/scripts/build-ui.sh` builds them with the firewall's other page assets, and
  `rust/scripts/box-ui` lists them, so `build-box.sh`, the release and `install.sh` carry them like
  the rest of `dist-ui/`.
- `cc-local` (`src/panel.rs`) serves `panel.js` and `panel.css` by name and `panel.html` for every
  other path outside `/api/`, so the panel's own routes load the app. No part of the path reaches the
  file system. The page is sent with `Cache-Control: no-store` and a CSP that allows only the
  firewall's own origin.
- A firewall in SaaS mode has the files too, and never serves them.
- `pnpm --filter @controlclaw/firewall-panel dev` runs the panel on Vite with `/api` proxied to
  `PANEL_API` (`http://127.0.0.1:8800` by default).
- The shared views get the firewall's API through `ConsoleApi` (`src/api/console-api.ts`), with one
  adapter per area in `src/api/`. An area with no API yet refuses every call; its page is "Coming
  soon", so no view makes one.
- Where the API and the console's view differ:
  - `/api/live` reads after a row's id, the shared list after a time: the adapter keeps the ids of
    the rows it handed over, by time. Rows the firewall `recorded` (not a request) are left out.
  - The API has no instructions-only save for the AI review: the adapter reads the settings and
    sends them back with the new words.
  - A change the console follows until it is confirmed with a code (rules, channels, apps, MCP
    servers, the exit) is applied at once here: the adapter hands the view the change already
    settled (`src/api/changes.ts`). An OAuth sign-in stays "waiting for you to sign in" until the
    callback tab says it finished, or 15 minutes pass.
  - The AI cards get `local: true`: no Notify, no review history, and "your own key" in place of
    the console's included AI.
  - "Today" on the Overview starts at midnight UTC, as the API counts it; the console starts it at
    the reader's own midnight.
  - The Overview's AI findings card says whether AI Log Review is on, read from `/api/egress/ai`.
