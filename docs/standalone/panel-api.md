# The local panel's API

A standalone firewall serves its panel's API on `LOCAL_PANEL_BIND` (default `127.0.0.1:8800`), next
to the admin login described in [`standalone-mode.md`](standalone-mode.md#the-admin-and-the-api). The local
panel (`packages/console-ui`) calls it through `@controlclaw/fw-api`.

- **Where it is defined.** One route table in Rust (`rust/crates/cc-local/src/api/`), one file per
  feature. Each route names the types it takes and gives.
- **The OpenAPI document** is made from that table: `packages/fw-api/openapi.json`. The TS types
  (`src/schema.ts`) are generated from it, and `src/index.ts` is a small typed client.
  - Change a route, then run `pnpm --filter @controlclaw/fw-api generate`.
  - A cc-local test fails while the checked-in document is not the table's.
- **Sign-in.** Every route needs the session cookie, and every write needs the `x-csrf-token`
  header. The client sets that header by itself after `/api/login`, `/api/setup` or `/api/session`.
- **Password.** `POST /api/admin/password {current, new}` changes the admin's password (the current
  one is checked as a login is, with its throttle; a wrong one is 400, not 401) and ends every other
  session. `mitm-agent reset-admin` on the machine is for a forgotten one ([`panel.md`](panel.md#forgot-the-password)).
- **Answers.**
  - A refusal is `{error}` with a 4xx status.
  - A change the firewall itself refused is 409, with its answer: `{ok: false, status, message}`.

## No confirmation codes

On the SaaS, a change that could weaken the firewall waits for a 6-digit code that a person gets
on Telegram or Slack. On a standalone firewall, the panel and the firewall are one program, so a
code adds nothing (plan §3).

- **A change from the signed-in admin applies at once.** The API asks the firewall's own handler
  (`<module>.propose`). The firewall makes a code as usual, but hands it back to the API instead of
  sending it to a person. The API confirms with it at once (`<module>.confirm`) and never shows it.
- **Still the module's own path.** Every change goes through each module's own proposal and
  confirmation, so a change is checked and applied exactly as on the SaaS.
- **Agents still need a person.** A change an agent asks for over MCP still needs a code.
- **How.** The admin's commands run in a scope of their own. In it, the firewall's list of people to
  send codes to is one entry, the admin, so a module that refuses when nobody can get a code
  (content rules, email rules, website logins) proposes as usual.

## Routes

The full list, with every field, is in `openapi.json`.

| Feature | Routes |
| --- | --- |
| Internet access | `GET`/`POST /api/egress/rules`; `PATCH`/`DELETE /api/egress/rules/{id}`; `POST /api/egress/rules/{id}/cycle` (allow, ask, block). The same checks as the console: a port only on a tunnel rule, AI review only on rules that let traffic out, the AI note only under review. The firewall reads a change at once, not at its next sync. |
| AI review | `GET`/`PUT /api/egress/ai`: on or off, log review, which model key and model, the caps, your instructions; `POST /api/egress/scan` runs the scan now. The review runs only with one of your own model keys. |
| Model keys | `GET`/`POST /api/llm/keys`, `DELETE /api/llm/keys/{provider}`: OpenAI, Anthropic, Google, OpenRouter or Vercel AI Gateway. The key is kept only by the firewall; the panel shows its last four characters. `POST /api/llm/agents/{vmId} {provider, model}` gives an agent its main model on that key: the firewall pushes it to the agent's vm-agent, with a stand-in for the key. |
| Activity | `GET /api/activity?source=network\|tools\|runs\|findings\|connectors&verdict=all\|allow\|ask\|block&q=&limit=&offset=`: rows, newest first, with the counts per verdict. |
| Overview | `GET /api/overview?range=1h\|24h\|7d`: requests per minute, blocked, response time (each with today, yesterday and 24 hourly values), this month's requests, the traffic chart, the newest requests, top hosts, traffic per agent, AI findings, rule and key counts. `GET /api/traffic?range=` and `GET /api/live?after=` are the chart and the list alone. |
| Pairing | `POST /api/pairing/codes` (`{name?, ttl_minutes?, address?, replace?}`: a one-time code for one machine), `GET /api/pairing/codes` (the ones still waiting, never with the code), `DELETE /api/pairing/codes/{id}`. `GET /api/pairing/address` (`{open, port, url, remoteUrl}`: where agents' machines reach the pairing endpoint, from `PAIR_BIND`, `PAIR_PROXY_ADDR`'s host and `WG_ENDPOINT`'s host; `url` is `null` when the firewall does not know it). The pairing itself is `POST /pair` on its own listener: see [`standalone-mode.md`](standalone-mode.md#pairing-an-agent). |
| Permission requests | `GET /api/requests?status=pending\|approved\|denied\|expired`; `POST /api/requests/{id}/resolve {decision: approved\|denied}`. The agent's next poll gets the answer. Each request has `resolvedBy` (`rule` for an Auto approve rule) and `ruleId`/`ruleName`, the rule that answered it or asked about it. No "Always allow" yet. |
| Content rules | `GET /api/content-rules` (the rules, the always-on ones, held messages, the AI's state, and `aiOn`); `POST /api/content-rules/change {change}` with `{op: put, rule}`, `{op: delete, id}` or `{op: ai}`; `POST /api/content-rules/try {text, direction, channel, draft?}`. They run on a standalone firewall too, now that its control plane is its own. |
| App rules | `GET /api/app-rules`; `POST /api/app-rules/change {change}` with `{op: put, rule, at?}`, `{op: delete, id}` or `{op: move, id, to}`; `GET /api/app-rules/mcp` (the MCP servers a rule can name). |
| Auto approve rules | `GET /api/security/rules` (`autoapprove.read`: the rules in the order they are read); `POST /api/security/rules/change {change}` with `{op: put, rule, at?}`, `{op: delete, id}` or `{op: move, id, to}`, applied at once. The rules are on the firewall. `GET /api/rule-metrics?range=24h\|7d\|30d&agentId=` counts how often each rule, and Every other request, matched (allowed, asked, blocked). |
| Email rules | `GET /api/email-rules`; `POST /api/email-rules/change {change}`: `add_sender`, `remove_sender`, `add_recipient`, `remove_recipient` (`{entry: {value, mailbox?}}`), `set_inbound_auth`, `set_outbound`, `set_mailbox_mode`. |
| Emergency stop | `GET /api/kill`; `POST /api/kill/engage {vmId?, confirm: "STOP"}`; `POST /api/kill/release {vmId?}`: with no `vmId`, every stop is released (the org-wide one, then each agent stopped on its own). |
| Web search | `GET /api/search`; `PUT /api/search/key {provider: tavily\|brave, key}`; `DELETE /api/search/key`. |
| Exit proxy | `GET /api/exit`; `PUT /api/exit` (your own account with a proxy provider: scheme, host, port, user name, password and the templates); `PATCH /api/exit {sticky?, capBytes?, country?}`; `DELETE /api/exit`; `POST /api/exit/check`. A rule sends a site through it with `exit: residential`. |
| Telegram and Slack | `GET /api/channels` (the bots, and who gets codes for agents' requests); `POST /api/channels {type, botToken, appToken?, label?, vmId?}` (Slack needs its app-level token too); `PUT /api/channels/{id}/token`; `POST /api/channels/{id}/assign {vmId}`, `POST /api/channels/{id}/unassign`; `POST /api/channels/{id}/pairing {code, senderId, label?}`; `DELETE /api/channels/{id}` (`?force=true` removes a bot whose agent cannot be told: an agent that is gone keeps a stand-in that no longer works). The list is the firewall's own (`channels.read`); the token stays there and only its last four characters are shown. |
| Connected apps | `GET /api/connectors`; `GET /api/connectors/setup/{service}`; `POST /api/connectors {service, apiKey \| secrets, extra?, label?, vmIds}`; `POST /api/connectors/oauth {service, clientId?, clientSecret?, extra?, authorizationOptionIds, vmIds}` (its answer has the address to send the browser to); `PUT /api/connectors/{id}`; `POST /api/connectors/{id}/reconnect`; `POST /api/connectors/{id}/assign {vmId, on}`; `DELETE /api/connectors/{id}`. Needs the connector runtime (OpenConnector) on the firewall. |
| MCP servers | `GET /api/mcp-servers`; `POST /api/mcp-servers {name, url, auth: none\|header\|oauth, headerName?, headerValue?, clientId?, clientSecret?, vmIds}`; `PUT /api/mcp-servers/{name}` (a header server's credential); `POST /api/mcp-servers/{name}/reconnect`; `POST /api/mcp-servers/{name}/assign {vmId, on}`; `POST /api/mcp-servers/{name}/tools`; `DELETE /api/mcp-servers/{name}`. The address must be `https://` on the internet. |
| Google | `GET /api/google` (the account, its services, the agents that have it, and `redirectUri`, the address to register in your OAuth client); `POST /api/google {clientId, clientSecret, services, gmailScope?, driveScope?, audience, projectId?, vmIds}` (your own OAuth client; the answer has the address to send the browser to); `POST /api/google/agents/{vmId} {granted}`; `POST /api/google/agents/{vmId}/push`; `PUT /api/google/services {services}`; `DELETE /api/google`. |
| AgentMail | `GET /api/agentmail`; `POST /api/agentmail/{action}` for `signup`, `claim`, `check`, `create`, `import`, `attach`, `senders`, `forget`, `delete`, `push`, with the action's body. An agent named by `vmId` needs its address (pairing gives it). AgentMail never asked for codes. |
| Website logins | `GET /api/logins` (never a password); `POST /api/logins/change {action: update\|delete, id, name?, sites?, vmIds?, mode?: swap\|type}`; `POST /api/logins/1password/sync`, `/disconnect`. A new login and its password are typed on the firewall's own Logins page: `POST /api/open {page: logins}`. |
| OAuth sign-ins | `POST /api/oauth/callback {state, code?, error?}`: what the provider sent to the panel's `/oauth/callback` page. The connectors, then the MCP servers, then Google take it: the one that started that sign-in finishes it. |
| Other | `GET`/`PUT /api/egress-rules` (the whole list at once), `GET`/`PUT /api/agents`, `GET /api/permissions`, `POST /api/permissions/answer`, `GET /api/activity/recent`, `POST /api/open`, `POST /api/commands`: see [`standalone-mode.md`](standalone-mode.md#the-admin-and-the-api). |

## Good to know

- **UTC.** Times are UTC, and "today" starts at midnight UTC.
- **Retention.** Activity is kept 30 days; the hourly counts are kept 13 months.
- **OAuth.** The provider sends the browser back to `<panel>/oauth/callback`, where `<panel>` is
  `LOCAL_PANEL_URL` (default `http://localhost:<port of LOCAL_PANEL_BIND>`). Register that address
  in your OAuth app.
  - Google takes only `https://` or `http://localhost`. Open the panel through an SSH tunnel to
    localhost (the default), or set `LOCAL_PANEL_URL` to its `https://` address (Caddy, Tailscale
    Serve). `GET /api/google` says when the address will not do (`redirectOk: false`, with
    `redirectProblem`), and `POST /api/google` refuses it.
  - The connector runtime gets the same address (`OOMOL_CONNECT_ORIGIN`, written from
    `LOCAL_PANEL_URL`: at each start in Docker, at install on a VM, in
    `/opt/controlclaw/standalone/connector-origin.env`).
- **AgentMail's address.** An inbox is written to the agent at the address this firewall paired it
  at; a `hostname` in a request is dropped, on its route and through `/api/commands`.
- **Not through `/api/commands`.** Model keys, the search key and the bots have routes of their own,
  which keep the panel's record of them; `/api/commands` refuses their actions. `kill.engage` there
  needs `confirm: "STOP"`, as on its route.
- **Every other site.** A new firewall allows every site and logs it. `PUT /api/egress/default`
  `{"effect": "block"}` blocks every site no rule names; `{"effect": "allow"}` lets them through
  again. The rule it writes (`block-all`) is not in `/api/egress/rules` and is changed only there.
- **Rules the firewall adds.** `/api/egress/rules` also lists the rules for the model keys and bots
  (`managed` names the key's provider or the bot's type, and the ids start with `managed:`). Changing
  or deleting one is refused (403); remove the key or the bot.
