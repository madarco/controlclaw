# The control-plane contract

Everything the firewall agent (`rust/bins/mitm-agent`) asks of a control plane, and every command a
control plane can send it. Two control planes implement it: the SaaS console (`apps/saas`) and, in a
standalone firewall, the local control plane built into the firewall (`cc-local`, plan
[`standalone-firewall.md`](../plans/standalone-firewall.md) §3).

Each endpoint and each command has a scope:

- **both**: any control plane serves or sends it;
- **SaaS only**: only the console does. A standalone firewall still registers the command, but nothing
  sends it, and it never calls the endpoint.

Where the rules live in code:

| What | Where |
| --- | --- |
| Endpoint bodies | `rust/crates/cc-contracts/src/control_plane.rs` (`ENDPOINTS`, `BEAT_FIELDS`, `ACTIVITY_SOURCES`) |
| Command actions and payloads | `rust/crates/cc-contracts/src/commands/` (`ACTIONS`, one file per family) |
| Endpoint cases | `rust/conformance/cases/cp/`, one per endpoint |
| SaaS harness for those cases | `apps/saas/scripts/conformance-cp.ts` |
| The local control plane | `rust/crates/cc-local` (`plane.rs`; `facade.rs` and `cc-local-contract` for the cases) |

Three tests keep the code and this page from drifting:

- the firewall agent's `registered_actions_match_the_contract` fails when an action or a beat field
  is added or removed without its row;
- `cc-contracts` parses every command payload in the conformance cases as its type;
- `cc-contracts` fails when an endpoint has no case, or a case's scope is not its endpoint's.

Run the endpoint cases with `rust/conformance/run.sh --cp`. It runs them against both control
planes:

- the SaaS routes, on the local Postgres that `pnpm test:db` uses;
- `cc-local` (`cc-local-contract`), which skips the cases and steps scoped SaaS only.

## Transport and auth

- The firewall calls the control plane over HTTPS. The control plane never calls the firewall: a
  firewall has no public port.
- Every call carries `Authorization: Bearer <box token>`:
  - an EdDSA JWT with header `{"alg":"EdDSA"}` and claims `{vmId, iat, exp}`;
  - it lives 30 s and is signed with the box's `vm_private_key.pem` (`cc_auth::sign::box_token`);
  - the control plane checks it against the public key it holds for `vmId`.
- Two calls use other auth:
  - `/register` uses the one-time bootstrap token from cloud-init;
  - `/api/mcp/agent` uses a token the firewall's gate signs per request.
- Refusals are JSON `{"error": "..."}`:

  | Status | When |
  | --- | --- |
  | 401 | No token, a token that does not verify, or an expired one. |
  | 403 | A box of the wrong role. The firewall is `mitm`; agents are `openclaw` and `gbrain`. On `/webhooks` this is 404 instead, so an agent cannot learn the endpoint exists. |
  | 400 | A body that does not parse. |

- The firewall finds the endpoints from its environment: `FIREWALL_URL`, `STORE_URL`, `RULES_URL`,
  `IDENTITIES_URL`, `PERMISSION_URL`, `ACTIVITY_URL`, `CA_URL` and `WEBHOOKS_URL`.
  - The store, rules, identities and webhooks also accept `file:` URLs: a file on disk instead of a
    control plane.
  - The Doctor and template endpoints are `FIREWALL_URL`'s folder joined with their name.

## Endpoints

| Endpoint | Methods | Scope | Local control plane |
| --- | --- | --- | --- |
| `/api/vm-agent/firewall` | POST | both | Accepts beats; `command` is always `null`, because config changes call the handlers directly. |
| `/api/vm-agent/egress-rules` | GET, POST | both | Rules and AI settings from its SQLite. |
| `/api/vm-agent/identities` | GET | both | Agents enrolled with a pairing code. |
| `/api/vm-agent/permission` | GET, POST | both | Requests answered in the local panel. |
| `/api/vm-agent/activity` | POST | both | SQLite. Raw rows are kept 30 days, the hourly rollup 13 months. |
| `/api/vm-agent/ca` | GET, POST | both | Serves the firewall's own CA. |
| `/oauth/callback` (a page) | GET | both | Served by the local panel. |
| `/api/vm-agent/store` | GET, POST | SaaS only | Not needed: the stores are on local disk. |
| `/api/vm-agent/webhooks` | GET | SaaS only | Webhooks are not in V1. |
| `/api/vm-agent/doctor` | POST | SaaS only | Doctor is not in V1. |
| `/api/vm-agent/template-proposal` | POST | SaaS only | No templates. |
| `/api/vm-agent/template-capture-draft` | POST | SaaS only | No templates. |
| `/api/vm-agent/register` | POST | SaaS only | Replaced by pairing. |
| `/api/vm-agent/ready` | POST | SaaS only | Replaced by pairing. |
| `/api/mcp/agent` | POST | SaaS only | The console's MCP for agents. |

### POST /firewall: the heartbeat

The firewall beats every 5 s (`FIREWALL_POLL_MS`), and again as soon as a command finishes.

- **Request** (`Heartbeat`):
  - `proxy`: `active`, `inactive` or `failed`.
  - `agent_version?` and `uptime_s?`.
  - `results?`: at most 20 `{command_id, ok, status, message, data?}`.
  - The fields each module adds, listed in `BEAT_FIELDS` with their scope:

    | Scope | Fields |
    | --- | --- |
    | both | `software`, `features`, `stores`, `kill`, `code_recipients`, `agents_reach`, `agents_moved`, `agentmail`, `residential` |
    | SaaS only | `access`, `auto_update`, `backup`, `disk_reseal`, `doctor_keys`, `included_ai`, `inventory`, `phone`, `team_chat`, `template_checks`, `update` |

- **Response** (`HeartbeatReply`): `{command: {id, action, payload} | null}`.
  - Each command is handed out once.
  - Its result rides a later beat.
- **Rules a control plane keeps:**
  - Never refuse a beat for a module field it cannot read. The beat is the firewall's only channel,
    so drop the field instead.
  - Drop a result whose `command_id` matches no command. A module's own reports carry a prefix
    instead of a command id: `llm.refresh:`, `channels.reconciled:`, `backup.done:`,
    `backup.restored:`, `included.no-credit:`, `google.token:`.
  - Delivery is at most once on the firewall's side: it does not persist pending results.
- **Errors**: 401, 403 (not `mitm`), 400 (no `proxy`).

### GET|POST /egress-rules

- **Response** (`EgressRulesReply`):
  - `rules`: the organization's enabled rules by `priority`, each as `cc_contracts::rules::Rule`:
    `{id, name, match_domain, match_path?, match_method?, match_port?, vm_id?, effect, exit?, exit_country?, priority, ai_review?, ai_policy?}`.
  - `ai`: the AI review settings (`AiSettings`), or `null` when it is off:
    `{credential_id, provider, model, checks, log_review, daily_call_cap, scan_interval_hours, auto_approve_per_hour, request_instructions, review_instructions}`.
- The firewall writes the rules to the proxy's `rules.json`.
- **Errors**: 401.

### GET /identities

- **Response** (`IdentitiesReply`):
  `{identities: [{vm_id, private_ip, name, hostname, access_hostname, status, role, agent_addr?}]}`.
  - `agent_addr` (cc-local only): `ip:port` where the firewall calls the agent's vm-agent, from pairing
    (`agent_listen`), else `<private_ip>:3100`. The SaaS sends none: there the firewall uses `hostname`.
  - Only agents (`openclaw`, `gbrain`) with a private address.
  - The proxy names an agent by the source address of its connection.
- **Errors**: 401, 403 (not `mitm`).

### /permission

- **POST to raise** (`PermissionRaise`):
  `{permission_id, kind?, scope?, summary?, host?, method?, path?, agent_vm_id?, expires_at?, …}`.
  - It is idempotent on `permission_id`: a second raise answers `deduped: true`.
  - A firewall may raise `access`, `email_recipient` and `app_call`.
  - An agent may raise `exec`, `plugin`, `system` and `meeting_request`.
- **POST to settle** (`PermissionResolution`): `{permission_id, resolution, resolved_by?}`. This is a
  request the box settled itself. A request that is already settled keeps its status.
- **Response to both POSTs** (`PermissionAck`): `{ok, status, deduped?}`.
- **GET `?permission_id=`** (`PermissionStatus`):
  `{status, expiresAt, kind, alwaysAllowed, validUntil}`.
  - `status` is `unknown` for an id this box may not read.
  - An agent may read the asks raised for it.
- **GET with no id**: `{pending: [{permission_id, summary, created_at}]}`, this box's open requests.
- **Errors**: 401, 403 (a kind the role may not raise; settling another box's request), 400.

### POST /activity

- **Request** (`ActivityBatch`): `{records: [...]}`, 1 to 500 records.
  - Each record has a `source`; a record without one is `egress`.
  - The sources a firewall ships, with their scope, are in `ACTIVITY_SOURCES`.
  - Duplicates are dropped by the record's id (`flow_id` for traffic).
- **Response** (`ActivityAck`): `{accepted, duplicates, skipped?, issue?}`.
- **Errors**: 401, 403 (a source the role may not ship), 400 (an empty or unreadable batch), 413.

### /ca

- **POST** (`CaPublish`), from the firewall: `{ca_cert, ca_sig, doctor_ssh_pub?, doctor_ssh_sig?}`.
  - `ca_sig` is the firewall's Ed25519 signature over the PEM.
  - The control plane stores it and cannot forge it.
- **GET** (`CaReply`), from an agent:
  `{caCert, caSig, pubKey, privateIp, doctor_ssh_pub, doctor_ssh_sig}`.
  - The agent checks `caSig` against the firewall key it pinned.
- **Errors**: 401, 403 (POST by an agent), 400 (no PEM or no signature).

### The OAuth callback

Connectors, MCP servers and Google send the person back to `<control plane>/oauth/callback?state&code`.
That page sends the firewall one command, which carries `{state, code?, error?}`:

- `connectors.callback`
- `mcpservers.callback`
- `google.callback`

It is a page, so it has no runner case. Its contract is those three payloads.

### SaaS-only endpoints

| Endpoint | What it does |
| --- | --- |
| `/store` | GET returns the sealed backup record. POST writes one: `{version, …}`, where `version` must be the stored one plus 1 (otherwise 409). |
| `/webhooks` | Returns `{hooks: [{id, enabled, name, limits}]}`, with no targets and no secrets. An agent gets 404. |
| `/doctor`, `/template-proposal`, `/template-capture-draft` | Uploads from the Doctor and from template sessions: 403 to an agent, 400 to a body that is not one. |
| `/register` | `Bearer <bootstrap token>` with `{vm_id, public_key}`. Registering the same key again is idempotent; another key gets 409. |
| `/ready` | The box says it is up. |
| `/api/mcp/agent` | The console's MCP server for agents. Each call is signed by the firewall's gate. |

The vm-agent has endpoints of its own (`/config`, `/disk`, `/doctor-pin`, `/template*`,
`/handle-certificate`, `/provision`). They are not part of this contract; the vm-agent's unmanaged mode
covers them.

## Commands

A command is `{id, action, payload}`.

- The firewall runs it, then puts `{command_id, ok, status, message, data?}` on its next beat.
- An unknown action fails with `unknown command <action>`.
- The SaaS console queues commands and hands them out on beats. The local control plane calls the
  same handlers directly.
- `start`, `stop` and `restart` (the proxy service) take `{}`. The control channel runs them itself,
  so they are not in the registry.

Most changes are a propose, then a confirm:

1. `<family>.propose` sends the change, with a `changeId`.
2. If someone can be asked, the firewall sends them a 6-digit code and answers `awaiting_code`.
   Otherwise (trust on first use) it applies the change at once.
3. `<family>.confirm {changeId, code}` applies it, and `<family>.cancel {changeId?}` drops it.

A standalone firewall skips the codes: its control plane and the firewall are one trust domain (plan
§3). Payloads are camelCase. A secret half (a bot token, an API key) travels in the payload's `secret`
field and is stored encrypted until it is handed out.

In the table below:

- **Payload** lists the fields the handler reads. `?` marks a field it can do without, `{}` means no
  fields, and `Confirm` is `{changeId, code}`.
- **Type** is the type in `cc_contracts::commands`. SaaS-only actions have none.
- **Handler** is the file under `rust/bins/mitm-agent/src/`.

### Both

| Action | Payload | Type | Handler |
| --- | --- | --- | --- |
| `agentmail.signup` | `{vmId, hostname, humanEmail, username, name?, allowedSenders?}` | `agentmail::Signup` | `channels/email/agentmail/mod.rs` |
| `agentmail.claim` | `{otpCode}` | `agentmail::Claim` | same |
| `agentmail.check` | `{}` | `agentmail::Check` | same |
| `agentmail.create` | `{vmId, hostname, username, name?, allowedSenders?}` | `agentmail::Create` | same |
| `agentmail.import` | `{apiKey, humanEmail, allowedSenders?}` | `agentmail::Import` | same |
| `agentmail.attach` | `{vmId, hostname, inboxId, name?}` | `agentmail::Attach` | same |
| `agentmail.senders` | `{inboxId, allowedSenders}` | `agentmail::Senders` | same |
| `agentmail.forget` | `{vmId?}` | `agentmail::Forget` | same |
| `agentmail.delete` | `{inboxId, confirmAddress?}` | `agentmail::Delete` | same |
| `agentmail.push` | `{vmId?}` | `agentmail::Push` | same |
| `agentmail.read` | `{}` | `Empty` | same |
| `ai.scan` | `{}` | `Empty` | `channels/ai/mod.rs` |
| `apps.read` | `{}` | `Empty` | `integrations/apps_rules/firewall.rs` |
| `apps.propose` | `{changeId, change: {op: put, rule, at?} \| {op: delete, id} \| {op: move, id, to}}` | `apps::Propose` | same |
| `apps.confirm` | `Confirm` | `Confirm` | same |
| `apps.cancel` | `{changeId}` | `ChangeRef` | same |
| `channels.propose` | `{changeId, kind, connectionId, type, hint?, label?, agent?, from?, pairing?, sender?, settings?, secret?}` | `channels::Propose` | `channels/chan/mod.rs` |
| `channels.confirm` | `Confirm` | `Confirm` | same |
| `channels.cancel` | `{changeId?}` | `Cancel` | same |
| `channels.push` | `{vmId, agentName?, hostname?}` | `channels::Push` | same |
| `channels.read` | `{}`: the connections, no secrets (`{connections: [{id, type, hint, label, assignedVmId, approvedSenders}]}`); what a standalone firewall's panel lists | `Empty` | `channels/mod.rs` |
| `connectors.read` | `{kind: setup\|connections, service?}` | `connectors::Read` | `integrations/connectors/firewall.rs` |
| `connectors.propose` | `{changeId, kind, service, serviceName?, connectionId?, label?, extra?, clientId?, authorizationOptionIds?, agents?, secret?}` | `connectors::Propose` | same |
| `connectors.confirm` | `Confirm` | `Confirm` | same |
| `connectors.cancel` | `{changeId?}` | `Cancel` | same |
| `connectors.callback` | `{state, code?, error?}` | `connectors::Callback` | same |
| `connectors.push` | `{vmId, hostname?, name?, privateIp?}` | `connectors::Push` | same |
| `connectors.forget` | `{vmId}` | `connectors::Forget` | same |
| `drive.propose` | `{changeId, kind, accountId?, account?, secret?, folder?, agents?}` | `drive::Propose` | `channels/drive/mod.rs` |
| `drive.confirm` | `Confirm` | `Confirm` | same |
| `drive.cancel` | `{changeId?}` | `Cancel` | same |
| `drive.push` | `{vmId, hostname?, name?}` | `drive::Push` | same |
| `drive.read` | `{}` | `Empty` | same |
| `email.read` | `{}` | `Empty` | `channels/email/rules.rs` |
| `email.propose` | `{changeId, change: {action, …}}` | `email::Propose` | same |
| `email.confirm` | `Confirm` | `Confirm` | same |
| `email.cancel` | `{changeId}` | `ChangeRef` | same |
| `exit.propose` | `{changeId, kind: add\|replace\|remove\|settings, provider?, scheme?, host?, port?, username?, password?, sticky?, capBytes?, country?, …}` | `exit::Propose` | `core/exit.rs` |
| `exit.confirm` | `Confirm` | `Confirm` | same |
| `exit.cancel` | `{changeId?}` | `Cancel` | same |
| `exit.check` | `{}` | `Empty` | same |
| `google.propose` | `{changeId, kind, client?, clientSecret?, services?, gmailScope?, driveScope?, audience?, projectId?, agents?}` | `google::Propose` | `channels/google/mod.rs` |
| `google.callback` | `{state?, code?, error?}` | `google::Callback` | same |
| `google.confirm` | `Confirm` | `Confirm` | same |
| `google.cancel` | `{changeId?}` | `Cancel` | same |
| `google.push` | `{vmId, hostname?, name?}` | `google::Push` | same |
| `google.forget` | `{vmId}` | `google::Forget` | same |
| `google.read` | `{}` | `Empty` | same |
| `health.probe` | `{vmId}` | `health::Probe` | `core/health.rs` |
| `kill.engage` | `{changeId, scope: org\|agent, vmId?, agents?}` | `kill::Engage` | `core/kill.rs` |
| `kill.release` | as `kill.engage` | `kill::Release` | same |
| `kill.confirm` | `{changeId, code, scope?, vmId?}` | `kill::Confirm` | same |
| `kill.cancel` | `{changeId?, scope?, vmId?}` | `kill::Cancel` | same |
| `llm.propose` | `{changeId, kind, credentialId, provider, providerName?, credKind?, placeholder?, hint?, label?, profileId?, swap?, oauth?, providerBlock?, allowedModels?, memory?, replaces?, agents?, secret?}` | `llm::Propose` | `channels/llm/mod.rs` |
| `llm.confirm` | `Confirm` | `Confirm` | same |
| `llm.cancel` | `{changeId?}` | `Cancel` | same |
| `llm.push` | `{vmId, name?, hostname?, embeddings?, refresh?, providerBlocks?}` | `llm::Push` | same |
| `logins.read` | `{}` | `Empty` | `integrations/logins/firewall.rs` |
| `logins.propose` | `{changeId, id, action: update\|delete, name?, sites?, vmIds?, mode?}` | `logins::Propose` | same |
| `logins.confirm` | `{id, changeId, code}` | `logins::Confirm` | same |
| `logins.cancel` | `{id, changeId?}` | `logins::Cancel` | same |
| `logins.1password_sync` | `{}` | `Empty` | same |
| `logins.1password_disconnect` | `{}` | `Empty` | same |
| `mcpcatalog.read` | `{}` | `Empty` | `integrations/mcp/mod.rs` |
| `mcpservers.read` | `{}` | `Empty` | `integrations/mcp/servers.rs` |
| `mcpservers.propose` | `{changeId, kind, name, url?, auth?, headerName?, clientId?, agents?, secret?}` | `mcp::Propose` | same |
| `mcpservers.confirm` | `Confirm` | `Confirm` | same |
| `mcpservers.cancel` | `{changeId?}` | `Cancel` | same |
| `mcpservers.callback` | `{state, code?, error?}` | `mcp::Callback` | same |
| `mcpservers.tools` | `{name}` | `mcp::Tools` | same |
| `mcpservers.push` | `{vmId}` | `mcp::Push` | same |
| `mcpservers.forget` | `{vmId}` | `mcp::Forget` | same |
| `rules.read` | `{}` | `Empty` | `channels/content_rules/firewall.rs` |
| `rules.propose` | `{changeId, change: {op: put, rule} \| {op: delete, id} \| {op: ai}}` | `rules::Propose` | same |
| `rules.try` | `{text, direction: in\|out, channel, draft?}` | `rules::Try` | same |
| `rules.confirm` | `Confirm` | `Confirm` | same |
| `rules.cancel` | `{changeId}` | `ChangeRef` | same |
| `search.propose` | `{changeId, kind: add\|replace\|remove, credentialId, provider, …, agents?, secret?}` | `search::Propose` | `core/search.rs` |
| `search.confirm` | `Confirm` | `Confirm` | same |
| `search.cancel` | `{changeId?}` | `Cancel` | same |
| `search.push` | `{vmId, name?, hostname?}` | `search::Push` | same |
| `search.forget` | `{vmId}` | `search::Forget` | same |
| `secrets.read` | `{}` | `Empty` | `channels/secrets.rs` |
| `secrets.propose` | `{changeId, action: create\|update\|replace\|delete, name, rules?, vmIds?, agents?, secret?}` | `secrets::Propose` | same |
| `secrets.confirm` | `{changeId, code, name}` | `secrets::Confirm` | same |
| `secrets.cancel` | `{changeId, name}` | `secrets::Cancel` | same |
| `secrets.retry` | `{}` | `Empty` | same |

`llm.*` with provider `gateway` (the included AI on ControlClaw's key) and `exit.*` with the ControlClaw
relay are SaaS only within a "both" action: a standalone firewall sends only the user's own keys and
the user's own exit proxy.

The field types and the `kind` values of each family are in its file under
`rust/crates/cc-contracts/src/commands/`.

### SaaS only

| Actions | Why | Handler |
| --- | --- | --- |
| `access.revoke`, `access.revoke_all` | Browsers signed in with console intents. A standalone firewall uses its own login. | `core/access.rs` |
| `apply.propose`, `apply.confirm`, `apply.cancel` | Templates, skills and shared notes. | `core/apply.rs` |
| `auto-update.propose`, `.confirm`, `.cancel`, `.disable` | Updates through our Ansible. | `core/auto_update.rs` |
| `backup.run`, `backup.firewall-run`, `backup.restore.{propose,confirm,cancel}`, `backup.recovery.{propose,confirm,cancel,rebind}`, `backup.firewall-restore`, `backup.firewall-restore.{confirm,cancel}` | Backups to our S3. | `core/backup.rs` |
| `devices.propose`, `.confirm`, `.cancel` | The Mac app's devices, through the console. | `core/devices.rs` |
| `doctor.propose`, `.confirm`, `.stop` | Doctor (later, with the user's own key). | `integrations/doctor/firewall.rs` |
| `firewall-update.propose`, `.confirm`, `.cancel` | Updates through our Ansible. | `core/firewall_update.rs` |
| `gbrain.propose`, `.confirm`, `.cancel`, `.disconnect` | The organization's brain. | `core/gbrain.rs` |
| `meetings.propose`, `.confirm`, `.cancel`, `.push` | Meetings (later: needs speech keys without our billing). | `channels/meetings.rs` |
| `phone.propose`, `.confirm`, `.cancel`, `.read`, `.push`, `.unassign`, `.forget`, `.disconnect` | Phone through our Twilio account (later: the user's own). | `channels/phone/firewall.rs` |
| `ssh.propose`, `.confirm`, `.cancel`, `.close` | Support SSH. | `core/ssh.rs` |
| `tailscale.propose`, `.confirm`, `.cancel` | Tailscale set up from the console. | `core/tailscale.rs` |
| `teamchat.propose`, `.confirm`, `.cancel`, `.disable`, `.push`, `.forget` | Team chat. | `integrations/teamchat/firewall.rs` |
| `tplcheck.propose`, `.confirm`, `.cancel` | Checks after a template was applied. | `integrations/doctor/tplcheck.rs` |
| `update.propose`, `.confirm`, `.cancel` | Agent updates through our Ansible. | `core/update.rs` |
| `update-all.auto`, `.propose`, `.confirm`, `.apply`, `.cancel` | Updates through our Ansible. | `core/update_all.rs` |
| `webhook.propose`, `.confirm`, `.cancel`, `.sync`, `.forget`, `.read` | Inbound webhooks (not in V1). | `core/webhooks.rs` |
