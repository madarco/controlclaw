# The local panel

A standalone firewall has its own web panel (`apps/firewall-panel`). The firewall serves it on the
same address as its API: `LOCAL_PANEL_BIND`, `127.0.0.1:8800` by default. The panel talks only to that
API ([`panel-api.md`](panel-api.md)) and draws the console's own screens from `packages/console-ui`.

## Opening it

- **On the firewall's machine**: open `http://localhost:8800`, or run `controlclaw open`.
- **On a server**: open an SSH tunnel, `ssh -L 8800:127.0.0.1:8800 <server>`, then
  `http://localhost:8800`.
- **`controlclaw install`, `up --here` and `up --all`**: the firewall's container listens on its own
  Docker network, and Docker publishes 8800 on this machine's loopback only. OpenClaw's container
  can't reach it.
- **`standalone/docker/compose.yaml`**: Docker publishes 8800 on the host's loopback. Inside the
  container the panel listens on every address (`LOCAL_PANEL_BIND=0.0.0.0:8800` with
  `LOCAL_PANEL_INSECURE=1`, both set in `compose.yaml`), since the host can't reach the container's
  loopback. The compose project's own network keeps containers on other networks (agents on Docker's
  default bridge) away from it. Don't attach agent containers to that network, and don't set these
  two with `docker run` on the default bridge. An agent that reaches the API could use up the
  sign-in tries and keep you out.
- **HTTPS with your own name** (Caddy, Tailscale Serve): proxy the name to `127.0.0.1:8800` and add it
  to `LOCAL_PANEL_HOSTS`. Any other name gets 421, for the page and the API alike.

## First run

1. While there is no admin, the firewall logs a one-time setup token at each start:
   `[cc-local] no admin yet: set the password with this one-time setup token …`. Only the newest line
   works. Read it with `journalctl -u controlclaw-mitm-agent` (install script) or
   `docker compose logs firewall` (Docker). Or run `controlclaw open` on the firewall's machine. It
   opens the panel with the newest token in the link's fragment (`#setup=<token>`), which the browser
   never sends to a server. The panel fills the token in and removes it from the address bar at once.
2. The panel asks for the token (already filled in when it came with the link) and the admin password
   (12 characters or more).
3. An AI model key, optional. The firewall's AI review runs only with one of your own keys.
4. The first agent, optional. The panel makes a one-time pairing code and shows the command to run on
   the agent's machine (`controlclaw connect`, see
   [`packages/cli/README.md`](../../packages/cli/README.md#pairing)). The code works once, within 10
   minutes, and the panel does not show it again.

## Signing in

- The password signs you in for 12 hours (the session cookie). **Sign out** ends every session.
- When the firewall ends the session (it expired, or someone signed out elsewhere), the next call
  answers 401. The panel shows "You were signed out", and after you sign in again you go on where you
  were.
- The panel allows ten tries a minute from one address and thirty from everyone, then shows "Too many
  tries. Wait a minute." Behind an SSH tunnel, every browser shares one address.

## Changing the password

- In **Settings → Admin password**, type the current password, then the new one twice (12 characters
  or more). The firewall checks the current one like a sign-in, so it counts toward the same ten tries
  a minute.
- The change signs out every other browser. The browser that made it stays signed in.

## Forgot the password

Run this on the firewall's machine, as the firewall's user:

- Install script: `sudo -u controlclaw mitm-agent reset-admin`
- Docker: `docker exec -u controlclaw <container> mitm-agent reset-admin`

It removes the admin password, ends every session and prints a new one-time setup token. The panel
then shows the first-run page again: type the token and a new password. The firewall needs no
restart, and nothing else changes (rules, keys and agents stay). Anyone with root on the machine can
do this, the same as reading the setup token from the log.

## Pages

| Page | Today |
| --- | --- |
| Overview | the console's Overview: requests per minute, blocked, response time, this month, the traffic chart, live requests, AI findings, top hosts and traffic per agent. Not here: Most used rules and the rules section (the firewall counts only its Auto approve rules, shown on Security rules) and Protected services. |
| Agents | the paired agents with their last 24 hours of traffic, and pairing codes (make, list, revoke) |
| Internet access | your own exit proxy (the Exit card: connect, settings, check, remove), the site rules (add, edit, cycle, delete; a change applies at once), then the AI Firewall and AI Log Review. AI Log Review has no Notify (no one to email; findings are in Activity) and no review history. |
| Security rules | Messages (content rules, with Try a message), Email, Websites, Integrations (app and MCP rules), Auto approve and Settings (the AI cards). Auto approve answers an agent's permission requests (shell commands, plugin actions, the firewall's own asks) with allow, ask or block; the first rule that matches decides, and **Every other request** asks you. The rules are kept on the firewall, as the Integrations rules are, and a change applies at once. Each rule shows how many requests it matched in 7 days. Only Auto approve has counts here. Email shows how to add a mailbox until AgentMail and Google come to the panel. App rules offer no action picker (the console's action catalog is not on the firewall). |
| Channels | Telegram and Slack bots, one agent at a time: add, replace the token, put on or take off an agent. A person is approved with the pairing code the bot sent them and their id on the channel (the firewall lists no waiting people). No WhatsApp yet. |
| Integrations | (needs `CONNECTOR_GATE_BIND`, the address agents reach the firewall's gates at; without it the firewall runs no connectors or MCP servers and the page says so) connected apps (the pinned OpenConnector catalog, searched in the panel; API key, credential and OAuth apps) and MCP servers. An OAuth sign-in opens the provider in a new tab, which comes back to `/oauth/callback`; that page hands the answer to the firewall and tells the first tab. |
| Permission requests | what agents asked, waiting first; Approve or Deny. A request an Auto approve rule answered is listed under All, with the rule; one a rule asked about names that rule. No "Always allow" yet: add the rule on Security rules. |
| Activity | Network, Tools, Runs, Findings and Integrations, with the verdict counts, a search and pages of 50. Network leaves out routine traffic (model calls and bot polling let through by the firewall's own rules with the key it put in, answered without an error) unless **Show routine traffic** is on (kept in this browser) or you search; the Overview still counts it. `GET /api/activity?routine=true` returns it too. |
| Settings | AI model keys (add, replace, remove) and the admin password. Its card for your own exit proxy says "Coming in a later update"; Internet access has the exit itself. |
| Website logins | the logins the firewall types in (name, sites, agents, whether it is swapped into the request or typed into the page), never a password; edit and delete; 1Password's read and disconnect. **Add a login** opens the firewall's own Logins page in a new tab (a one-time link), where the password is typed. |
| Google (Integrations → Google) | your own OAuth client: the redirect address to register (and, when Google would refuse it, why: Google takes only https or http on localhost; open the panel through an SSH tunnel, or set `LOCAL_PANEL_URL`), the client's JSON, the services and scopes, Sign in with Google in a new tab, then the services (turning one off at once; one Google was not asked for needs Connect again) and the agents (with Send again). No Drive folders and no Gmail push yet. |
| AgentMail (Integrations → AgentMail) | a new account (AgentMail emails a code to claim it) or an existing key; inboxes per agent (create, give, send again, take off, delete with the address typed). Only paired agents get an inbox: it is set up at the address pairing gave them. Who may email an inbox is in Security rules → Email. |

A page whose API the firewall does not have says "Coming soon".

**Stop** in the header stops every agent (no model calls, no web, no channels) after you type STOP.
A red line across the top says so until you press **Start again**.

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
- The app logos (`packages/console-ui/connector-icons/`) go in one more flat file,
  `connector-icons.pack`, written by `build-fw-files.mjs` and listed in `box-ui`. `panel.rs` reads it
  once and serves `/connector-icons/<version>/<service>.webp` from it, cached for a year (the
  version is in the path). Any other path under `/connector-icons/` is a 404.
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
