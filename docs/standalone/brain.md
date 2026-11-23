# The brain on a standalone firewall

A brain is a [GBrain](https://github.com/garrytan/gbrain) your agents share. One agent saves what it
learned, and another one finds it later. On a standalone firewall the brain runs on a machine of its
own, behind the firewall, and you choose which agents may use it on the panel's **Brain** page, or
with the API routes below. The page has the same controls: the agents and their scope, the lock, the
model, the name of the brain's pages and a button that opens them signed in.

## Set up a brain

There are two ways, both with sudo:

| | Command | What it does |
| --- | --- | --- |
| A new brain | `controlclaw brain install` | GBrain and Postgres (with pgvector) in Docker, and ControlClaw's vm-agent next to them. |
| A GBrain you already run | `controlclaw brain connect` | ControlClaw's vm-agent next to your GBrain, and GBrain's traffic sent through the firewall. GBrain and its data stay where they are. |

Either way the brain pairs with the firewall as **the brain** (one per firewall). Give it the name its
pages will have with `--pages-name brain.example.com` (see [The brain's pages](#the-brains-pages)).

### Install a brain

Docker only for now, on Linux, with sudo. GBrain needs about 1 GB of RAM; a 4 GB machine is enough
for tens of thousands of pages.

#### Next to the firewall

On the machine where `controlclaw install` (or `up --all`) runs the firewall:

```bash
sudo controlclaw brain install
```

No code to type: it pairs with the firewall on this machine by itself. It:

- builds GBrain's image here: Ubuntu 24.04 and GBrain 0.60.723.0, downloaded from GitHub and checked
  by sha256 (the same pin as ControlClaw's own brains). The build needs the internet; the brain
  itself does not have it afterwards;
- starts three containers in the Compose project `controlclaw-brain` (`/etc/controlclaw/brain`):
  `postgres` (Postgres 16 with pgvector, data in the volume `controlclaw-brain_postgres`), `gbrain`
  (GBrain's home in `controlclaw-brain_gbrain`) and `gate`;
- keeps `gbrain` on the brain's own internal network, with Postgres and two relays: `egress`, the one
  that is also on the firewall's `agents` network (at `172.31.251.20`, the brain's identity at the
  firewall) and passes only the model calls and DNS to the firewall's proxy, and `gate`, which publishes
  GBrain on this machine's loopback for the vm-agent. GBrain reaches nothing else, and no OpenClaw on
  `agents` reaches GBrain;
- installs the vm-agent in brain mode as `controlclaw-brain-agent.service` (root: it runs GBrain's
  helpers with `docker exec`). The firewall calls it on `172.31.252.1:3103`, from its own address only.

#### On another machine

The firewall calls the brain's vm-agent, so across a network the brain needs WireGuard, as
[remote OpenClaw machines](quickstart-remote.md) do: the firewall runs with `--wireguard`. In the
panel make a pairing code **for the brain**, or on the firewall:

```bash
sudo -u controlclaw mitm-agent pair-code --role gbrain --name brain
```

Then on the brain's machine:

```bash
sudo controlclaw brain install --firewall http://<firewall address>:8801
```

It asks for the code (never type it on the command line), pairs, brings up the tunnel `cc-wg0`, and
then sets up the same containers. Here `gbrain` reaches only the `gate` container, which passes its
model calls and DNS to the firewall's tunnel address. The brain's identity at the firewall is its
tunnel address.

With the firewall on this machine, `brain connect` pairs at this machine's own address toward the
firewall, which an OpenClaw connected here in host mode already has: then the pairing is refused
rather than taking its place. Use `brain install` there, which has an address of its own.

An agent's code does not pair a brain, and a brain's code does not pair an agent: make the code for
what you are connecting. A firewall has one brain. Pairing a second one is refused unless the code
says `--replace`, which removes the first from the firewall.

### Connect a GBrain you already run

```bash
sudo controlclaw brain connect                                  # the firewall on this machine
sudo controlclaw brain connect --firewall http://<fw>:8801      # a firewall elsewhere, over WireGuard
```

What your GBrain needs first:

- it runs as a **systemd system service** (`gbrain serve --http --port <port>`), under its **own
  user**, not root. `connect` finds the service by what it runs; `--gbrain-unit <unit>` names it,
  and `--gbrain-port` gives the port when the unit does not say `--port`;
- its database works with its own settings (`~/.gbrain/env` or the unit's `EnvironmentFile`), and is
  **on this machine**: GBrain will reach nothing but this machine and the firewall, and Postgres does
  not go through a proxy. A database elsewhere (Supabase, a managed Postgres) is refused before
  anything changes; use `brain install` then;
- it embeds with `openai:text-embedding-3-small`, the one embedding model the firewall lets the brain
  use. Another one is refused before anything changes: moving means embedding every page again;
- it is not on a machine that already has a tunnel to a firewall (`connect --mode remote`): a brain
  over WireGuard needs the machine's one tunnel.

What `connect` does:

- installs GBrain's helpers in `/usr/local/bin/cc-gbrain-*` (they mint and revoke the agents' tokens,
  set the model, run the pages' export and import), and refuses if they are already there;
- sets GBrain's models to the brain's (GPT-5.6 Luna for routine work, Terra for deep answers), and
  remembers what they were;
- adds a drop-in to GBrain's unit (`/etc/systemd/system/<unit>.d/controlclaw-brain.conf`): the
  firewall's proxy and CA, the model key file (`/etc/controlclaw/brain/gbrain/gbrain.env`, 0640
  `root:<GBrain's group>`, with a stand-in key from the start, so GBrain's own key is out of effect
  until the firewall gives it yours), and `IPAddressDeny=any` with only loopback and
  the firewall allowed. GBrain can then reach nothing but the firewall and this machine's own
  services. Anyone with root here can remove the drop-in;
- installs the vm-agent in brain mode, as for an install, and restarts GBrain.

Your GBrain's own schedule (an autopilot or a cron job) stays as it was; `connect` adds no nightly run.

## What you need

- **A standalone firewall** with the tools gate on: `CONNECTOR_GATE_BIND` set, the same setting MCP
  servers need. Agents reach the brain through it.
- **A brain paired with the firewall.** `controlclaw brain install` and `controlclaw brain connect`
  set one up and pair it. A brain you set up by hand can be added with `PUT /api/agents`, role
  `gbrain`, with the address the firewall calls its vm-agent at (`agent_addr`).
- **Agents added with `controlclaw connect`**, whose vm-agent is from this release or later. Nothing
  else has to be installed on them.

## Turning the brain on for an agent

```
PUT    /api/brain/agents/{vmId}   {"scope": "read_write"}   or   {"scope": "read"}
DELETE /api/brain/agents/{vmId}
GET    /api/brain
```

- **Read and write** lets the agent search the brain and save to it. **Read only** lets it search,
  and the brain refuses its saves.
- Every agent you turn on sees everything the other agents saved. That is the point of the brain.
  Leave off an agent you would not trust with your other agents' notes.
- From the signed-in panel a change applies at once, with no code, as other standalone settings do.
- Turning an agent on adds one entry to its OpenClaw config, `mcp.servers.gbrain`, and OpenClaw
  restarts once to pick it up. Turning it off removes that entry and nothing else, so the config is
  as it was before.
- `GET /api/brain` lists every agent with its scope, whether it is under the emergency stop, and
  whether the firewall can reach its vm-agent to turn it on.

## How an agent reaches the brain

The agent's entry is a plain address on the firewall's tools gate, `http://<gate>:3940/brain/mcp`,
with no password in it. `<gate>` is the address the agent already uses for the firewall's gates: the
tunnel address over WireGuard, the container's gate in Docker, the firewall's private address on
the same network.

For each call the firewall:

1. knows the agent by the address the call came from, as for MCP servers;
2. refuses it if the agent is not turned on, is under the emergency stop, or the brain is locked;
3. signs a token for that one call and sends it on to the brain's vm-agent;
4. writes one line in Activity: the agent, the time, how much went each way, the answer's status.

The brain takes a call only from the firewall's address and only with the firewall's token for that
exact call. The token names the agent, so each agent keeps its own key and scope on the brain. GBrain
itself listens only on the brain's own loopback. An agent or a machine on the same network that calls
the brain directly is refused.

Limits on each call:

| Limit | Value |
| --- | --- |
| Request body | 4 MB, sent within 30 seconds. A larger or slower call gets 413. |
| Calls on their way at once | 4 from one agent, 16 from all agents together. One more gets 429 at once, until the brain has one of them. |
| Silence while the brain answers | 600 seconds. A long `think` can take minutes, and answers can be a stream. |
| Calls a minute | 600 from one agent's address, 3,000 from all agents together, then 429 for the rest of the minute. |

A refusal for one of these limits is `{"error"}` with words the agent can read, and a 429 says when
to try again (`Retry-After`). A call refused for going over its budget leaves no line in Activity.
The brain keeps its own limits on top (6 calls on their way per agent, 24 in all), and keeps room for
the firewall's own calls to it, so agents' calls never crowd out the lock or a connection.

**Content rules do not read brain traffic yet.** The firewall sees each call and can stop it, but it
does not check what an agent saves to the brain or what it finds there against your content rules.
Give **Read only** to an agent whose saves you would not want the others to read.

## Locking the brain

```
PUT /api/brain/lock   {"locked": true}    or   {"locked": false}
```

The lock takes every agent off the brain at once. Their connections are kept, so unlocking puts
them back without turning each one on again. The emergency stop does the same for the agents it
stops: a stopped agent's next call to the brain is refused, and releasing the stop lets it back.
The firewall refuses the call itself and also tells the brain, so the brain refuses it even if a call
got past the firewall.

## The model and the numbers

- `GET` and `PUT /api/brain/model {"model"}`: the model for the brain's own work, the nightly run
  and the rewording of searches. The brain restarts once to take it. The key it uses is your own,
  through the firewall.
- `GET /api/brain/status`: whether GBrain and its database are up.
- `GET /api/brain/overview`: searches and saves today, yesterday and per hour, the median time of
  a search, saves per agent and per day over 30 days, and the brain's page counts by kind. A save
  the brain refused is not counted. The calls are counted from the firewall's own line for each one,
  which names the tool (`search`, `put_page`) and never what was saved or searched for. The page
  counts come from the brain itself, when it sends them to the firewall. Days are UTC.

### Its key

The brain uses a model for its own work: making pages searchable by meaning (`text-embedding-3-small`),
the nightly run and rewording searches (GPT-5.6 Luna), and deep answers (GPT-5.6 Terra). It pays with
**your** key, the one the firewall holds:

- your **Vercel AI Gateway** key if the panel has one (Settings → AI model keys), else your **OpenAI**
  key;
- the brain never sees the key. It gets a stand-in, and the firewall swaps it for the real key on the
  provider's host, for the brain's three models only. Any other model the brain asks for is refused;
- the firewall gives the brain its key within a minute of pairing, after you add, replace or remove a
  key, and every hour. With no key, the brain keeps working by keyword, and searching by meaning comes
  back once you add one.

## The brain's pages

The brain serves its own pages: Pages (every page, to read and edit), Lately, Ask, Import and Export.
The firewall relays them to your browser, because the brain is on the firewall's private side where
your browser cannot reach it.

1. **Give the pages a name** with a dot and no port, such as `brain.example.com`:

   ```
   PUT /api/brain/pages   {"hostname": "brain.example.com"}
   ```

   The brain must have the same name: `brain install` and `brain connect` take it as
   `--pages-name brain.example.com`. To change it later, set `gbrain.pages_name` in
   `/etc/controlclaw/brain/agent.json` and restart `controlclaw-brain-agent`.
   With two different names the brain refuses the sign-in. The name is set once: the firewall keeps
   a machine's first name, so to use another, pair the brain again.

2. **Put HTTPS for that name in front of the relay.** The firewall serves the pages on
   `BRAIN_PAGES_BIND`, `127.0.0.1:8803` by default (`off` closes it). In Docker the image listens on
   `0.0.0.0:8803` inside the container and publishes it on the host's loopback. With Caddy on the
   firewall's machine:

   ```
   brain.example.com {
     reverse_proxy 127.0.0.1:8803
   }
   ```

   Tailscale Serve works too. The firewall's own pages need the same kind of name (see
   [`standalone/README.md`](../../standalone/README.md#opening-a-page)).

3. **Open them:** `POST /api/brain/open {"page": "pages"}` answers a link, or on the firewall:

   ```bash
   sudo -u controlclaw mitm-agent open brain
   ```

   The link works once, within 60 seconds. It signs your browser in to the firewall, then to the
   brain, and lands on Pages, whichever page you asked for (`lately`, `ask`, `import`, `export`
   are one click away there). The session lasts 12 hours.

`{"page": "admin"}` (or `mitm-agent open brain-admin`) opens GBrain's own admin page instead, when
the brain serves it behind its sign-in.

The relay passes only what a browser uses: the sign-in steps, the pages and their API, the page
files, and GBrain's admin page. The routes the firewall uses to manage the brain answer 404 there.

A brain from `brain install` or `brain connect` serves GBrain's admin page behind the same sign-in:
the admin link lands on GBrain's own single-use link, and `/admin` then needs this browser's session
on the brain, as on the SaaS. `brain install` gives GBrain the pages' name as its public address, so
its links stay on that name. For `brain connect`, GBrain needs its owner credential
(`GBRAIN_ADMIN_BOOTSTRAP_TOKEN` in its environment) to make that link, and its own `--public-url`
should be `https://<the pages' name>`.

## Undo it

```bash
sudo controlclaw brain disconnect           # every step undone, and the firewall forgets the brain
sudo controlclaw brain disconnect --purge   # an installed brain: also delete what it learned
```

- After `brain install`, the containers, the image, the vm-agent, the tunnel and the files go. The
  two volumes stay without `--purge`, and a later `brain install` uses them again.
- After `brain connect`, the helpers, the drop-in, the vm-agent and the tunnel go, the tokens the brain
  made in GBrain (its agents' and its pages') are revoked, GBrain's models are put back as they were
  (unset again where they were GBrain's defaults), and GBrain is restarted. Its pages are never touched.
- `sudo controlclaw brain status` shows the vm-agent, the containers or GBrain's unit, and the tunnel.

## Not on a standalone firewall

- **Save what it learns automatically.** It needs the `cc-instructions` plugin on the agent, which
  `controlclaw connect` does not install. Agents save when they decide to, or when you ask them.
- **Outside AI apps** (Claude, ChatGPT, Cursor on the brain's own MCP address).
- **Backups of the brain**, its encrypted disk, sizes and billing.
- **Activity and the brain's counts by kind on the Overview** for now: the brain does not send them to
  the firewall yet, so its page counts say "counting pages".
- **Updates of GBrain**: a new GBrain comes with a new release of the CLI (`brain disconnect`, then
  `brain install`, keeps the data).
- **The pages' "Back" link** goes to the panel's Brain page at `http://localhost:8800` (the panel
  through an SSH tunnel), whatever address you open the panel at.
- **An arm64 brain**: GBrain's release has an x86-64 binary only in this pin.

## Good to know

- An agent turned on in Docker reaches the gate through the same address as for MCP servers. If an
  agent was paired before `firewall.gate` existed in its config, turning it on fails and says so: run
  `controlclaw connect` on it again.
- The firewall's address for the brain's vm-agent comes from pairing. If the brain moves, pair it
  again; the agents' entries point at the firewall, so they do not change.
- See [`panel-api.md`](panel-api.md) for every field, and
  [`docs/plans/standalone-brain.md`](../plans/standalone-brain.md) for how this was built.
