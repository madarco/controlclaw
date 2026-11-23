import { useState, type FormEvent } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "@tanstack/react-router";
import { toast } from "sonner";
import { BookOpen, Brain, ExternalLink, Lock, Unlock } from "lucide-react";
import { BrainAgentsCard, BrainModelPicker, BrainOverview, ago, useBrainOverview } from "@controlclaw/console-ui/brain";
import { emptyOverview } from "@controlclaw/console-ui/lib/brain-stats";
import { PageHead } from "@controlclaw/console-ui/kit/PageHead";
import { AnchorTabs, Card, CodeField, KV, Pill, Sec, useHashTab, type PillTone } from "@controlclaw/console-ui/kit/console-ui";
import { StatusHero, type HeroTone } from "@controlclaw/console-ui/kit/StatusHero";
import { Button } from "@controlclaw/console-ui/ui/button";
import { Input } from "@controlclaw/console-ui/ui/input";
import { formatBytes } from "@controlclaw/console-ui/lib/format";
import { openInNewTab } from "@controlclaw/console-ui/lib/open-in-new-tab";
import { BRAIN_KEY, brainQuery, brainSource, pagesHostname, type BrainPageId, type PanelBrainView } from "../api/brain";
import { errorText } from "../api/client";
import { FormError } from "../auth/AuthFrame";

/**
 * The Brain page (docs/plans/standalone-brain.md part C): the console's Overview, Agents and Model
 * (`@controlclaw/console-ui/brain`) on this firewall's brain, the button that opens the brain's own
 * pages signed in, and what a standalone brain does not have.
 */

const TABS = ["overview", "agents", "settings"] as const;
const NO_NUMBERS = emptyOverview();
const TAB_LABEL: Record<(typeof TABS)[number], string> = { overview: "Overview", agents: "Agents", settings: "Settings" };

type Brain = NonNullable<PanelBrainView["brain"]>;
type Heading = { tone: HeroTone; pill: PillTone; label: string; text: string; pillText: string };

/**
 * What the brain is doing, in one heading. The emergency stop explains everything else, so it comes
 * first; the admin's own lock comes after a brain that is down, which the admin needs to hear about.
 */
export function brainHeading(b: Brain): Heading {
  if (b.stoppedAll) {
    return {
      tone: "block",
      pill: "block",
      label: "Locked by the emergency stop",
      text: "No agent can search the brain or save to it. Release the stop to unlock it.",
      pillText: "Locked",
    };
  }
  if (!b.reachable) {
    return {
      tone: "ask",
      pill: "ask",
      label: "Brain not responding",
      text: `The firewall can’t reach the brain’s machine. Check that the machine is on and its containers are running.${b.error ? ` The firewall says: ${sentence(b.error)}` : ""}`,
      pillText: "Not responding",
    };
  }
  if (!b.service?.active) {
    return { tone: "ask", pill: "ask", label: "Brain stopped", text: "GBrain isn’t running on its machine. Nothing can search it or save to it.", pillText: "Stopped" };
  }
  if (b.locked) {
    return {
      tone: "block",
      pill: "block",
      label: "Brain locked",
      text: "No agent can search the brain or save to it. Their connections are kept: unlock it in Settings to let them back.",
      pillText: "Locked",
    };
  }
  return {
    tone: "brand",
    pill: "allow",
    label: "Your brain is running",
    text: b.agents.some((a) => a.connection) ? "Your connected agents search it and save to it." : "It is ready. Turn it on for your agents in the Agents tab.",
    pillText: "Running",
  };
}

const sentence = (t: string) => (/[.!?]$/.test(t.trim()) ? t.trim() : `${t.trim()}.`);

/** The brain answers and GBrain runs: its pages open and its model can change, locked or not. */
const running = (b: Brain) => b.reachable && b.service?.active === true;

/** Opens one of the brain's pages in a new tab, signed in with a one-time link. */
export function openBrainPage(page: BrainPageId) {
  void openInNewTab(() => brainSource.openPages({ page }), "Couldn’t open the brain’s pages");
}

export function BrainPage() {
  const q = useQuery(brainQuery);
  return (
    <div data-testid="brain-page">
      <PageHead title="Brain" sub="One shared memory for your agents. They search it and save to it, so what one learns the others can use." />
      {q.isPending ? (
        <Card className="px-4 py-6 text-[13.5px] text-ink-2">Loading…</Card>
      ) : q.error ? (
        <Card className="px-4 py-4">
          <FormError>{errorText(q.error)}</FormError>
        </Card>
      ) : q.data.brain ? (
        <BrainView brain={q.data.brain} />
      ) : (
        <AddBrain />
      )}
    </div>
  );
}

function AddBrain() {
  return (
    <Card className="p-5" data-testid="brain-add">
      <div className="text-[15px] font-semibold text-ink">Add a brain</div>
      <p className="mt-1 max-w-[66ch] text-pretty text-[13.5px] text-ink-2">
        A brain is GBrain on a machine of its own, behind this firewall. Run one of these on that machine, with a pairing code
        from the <Link to="/agents" className="font-semibold text-brand underline-offset-2 hover:underline">Agents</Link> page.
      </p>
      <div className="mt-4 grid gap-3 lg:grid-cols-2">
        <div className="min-w-0 rounded-[12px] border border-line p-4">
          <div className="text-[14px] font-semibold text-ink">A new brain</div>
          <p className="mt-1 text-[13px] text-pretty text-ink-2">Installs GBrain and its database in Docker, then pairs with this firewall.</p>
          <CodeField className="mt-3" text="controlclaw brain install" data-testid="brain-add-install" />
        </div>
        <div className="min-w-0 rounded-[12px] border border-line p-4">
          <div className="text-[14px] font-semibold text-ink">A GBrain you already run</div>
          <p className="mt-1 text-[13px] text-pretty text-ink-2">Adds only ControlClaw’s agent next to it. GBrain and what it knows stay where they are.</p>
          <CodeField className="mt-3" text="controlclaw brain connect" data-testid="brain-add-connect" />
        </div>
      </div>
    </Card>
  );
}

function BrainView({ brain: b }: { brain: Brain }) {
  const client = useQueryClient();
  const refresh = () => void client.invalidateQueries({ queryKey: BRAIN_KEY });
  const [tab, setTab] = useHashTab("overview", TABS);
  // A lock keeps the agents out, not the admin: the counts, the pages and the model still work.
  const up = running(b);
  const read = useBrainOverview(null, true, b.vmId);
  // A brain that is down may never answer the count: zeros then, not a skeleton for good.
  const stats = read ?? (up ? null : NO_NUMBERS);
  const heading = brainHeading(b);
  const connected = b.agents.filter((a) => a.connection).length;
  const pages = stats?.latest?.pageCount;
  const saved = ago(stats?.lastSavedAt ?? null);
  const healthy = heading.tone === "brand";
  const label = healthy && pages != null ? `Remembering ${pages.toLocaleString("en-US")} ${pages === 1 ? "page" : "pages"}` : heading.label;
  const meta = healthy
    ? [`${connected} ${connected === 1 ? "agent" : "agents"} connected`, saved ? `last saved ${saved}` : null, pages == null ? "counting pages, first count within 15 minutes" : null]
        .filter(Boolean)
        .join(" · ")
    : null;

  return (
    <>
      <StatusHero
        icon={Brain}
        tone={heading.tone}
        label={<span data-testid="brain-status-label">{label}</span>}
        text={healthy ? (connected === 0 ? heading.text : null) : heading.text}
        meta={meta ? <span data-testid="brain-status-meta">{meta}</span> : null}
        data-testid="brain-status"
        badges={
          <Pill tone={heading.pill} testId="brain-pill">
            {heading.pillText}
          </Pill>
        }
        actions={
          running(b) && b.pages ? (
            <Button size="sm" onClick={() => openBrainPage("pages")} data-testid="brain-action-pages">
              <BookOpen className="h-3.5 w-3.5" /> Pages
            </Button>
          ) : null
        }
      />

      <AnchorTabs tabs={TABS.map((id) => ({ id, label: TAB_LABEL[id] }))} active={tab} onSelect={setTab} className="mt-4" data-testid="brain-tabs" />

      {tab === "overview" ? <BrainOverview view={stats} running={up} /> : null}

      {tab === "agents" ? (
        <div className="mt-5">
          <BrainAgentsCard
            agents={b.lockedByAdmin ? b.agents.map((a) => ({ ...a, stopped: true })) : b.agents}
            change={b.change}
            canManage
            brainUp={running(b)}
            usage={stats?.agents}
            title="Agents"
            intro="The OpenClaw machines connected to this firewall. Each sees everything the others saved. Turning one on or off, or changing what it may do, applies at once."
            captureOffNote={b.autoSaveOff ?? undefined}
            onChanged={refresh}
          />
        </div>
      ) : null}

      {tab === "settings" ? <Settings brain={b} diskUsed={stats?.latest?.diskUsedBytes ?? null} diskFree={stats?.latest?.diskFreeBytes ?? null} onChanged={refresh} /> : null}
    </>
  );
}

function Settings({ brain: b, diskUsed, diskFree, onChanged }: { brain: Brain; diskUsed: number | null; diskFree: number | null; onChanged: () => void }) {
  return (
    <>
      <Sec title="Model" className="mt-5">
        {b.needsKey ? (
          <Card className="p-5" data-testid="brain-model-needs-key">
            <p className="max-w-[70ch] text-pretty text-[13.5px] text-ink-2">
              The brain needs a model for its own work: the nightly run that reads new pages and tidies up, and the rewording of
              searches. Add an OpenAI or Vercel AI Gateway key in{" "}
              <Link to="/settings" hash="ai-models" className="font-semibold text-brand underline-offset-2 hover:underline">
                Settings
              </Link>
              . The brain uses it through this firewall and never sees the key.
            </p>
          </Card>
        ) : (
          <BrainModelPicker
            model={b.model ?? ""}
            models={b.models}
            intro="The model the brain uses for its own work: the nightly run that reads new pages, finds facts and tidies up, and the rewording of searches. It runs on your own model key, through this firewall, which keeps the key."
            canManage
            running={running(b)}
            onChanged={onChanged}
          />
        )}
      </Sec>

      <Sec title="Machine" className="mt-6">
        <Card className="px-5 py-2" data-testid="brain-details">
          <KV
            rows={[
              ["Name", b.name],
              b.address ? ["Address", b.address, true] : null,
              ["Added with", b.origin === "connect" ? "controlclaw brain connect" : b.origin === "install" ? "controlclaw brain install" : "—", true],
              ["Software", b.version ?? "Not reported yet"],
              ["Disk", diskUsed != null && diskFree != null ? `${formatBytes(diskUsed)} of ${formatBytes(diskUsed + diskFree)} used` : "Measured with the first count"],
            ]}
          />
        </Card>
      </Sec>

      <Sec title="Its own pages" className="mt-6" sub="Served by the brain itself: every page to read and edit, Lately, Ask, Import and Export.">
        {b.pages ? <PagesLinks brain={b} /> : <PagesName onChanged={onChanged} />}
      </Sec>

      <Sec title="Lock" className="mt-6">
        <LockCard brain={b} onChanged={onChanged} />
      </Sec>

      <Sec title="Not on a standalone firewall" className="mt-6">
        <Card className="p-5" data-testid="brain-not-standalone">
          <ul className="list-disc space-y-1.5 pl-5 text-pretty text-[13.5px] text-ink-2">
            <li>Sizes and billing: the brain runs on your own machine, at the size you gave it.</li>
            <li>Restart, reboot or resize from here: do it on the brain’s machine.</li>
            <li>Backups: back up its Docker volume yourself for now.</li>
            <li>An encrypted disk that the firewall unlocks.</li>
            <li>“Save what it learns automatically”: it needs ControlClaw’s plugin on the agent, which connecting OpenClaw does not install.</li>
          </ul>
        </Card>
      </Sec>

      <Sec title="Remove the brain" className="mt-6">
        <Card className="p-5" data-testid="brain-remove">
          <p className="max-w-[70ch] text-pretty text-[13.5px] text-ink-2">
            Run this on the brain’s machine. Your agents are disconnected from it first. What it knows stays on that machine.
          </p>
          <CodeField className="mt-3" text="controlclaw brain disconnect" />
        </Card>
      </Sec>
    </>
  );
}

function PagesLinks({ brain: b }: { brain: Brain }) {
  const on = running(b);
  return (
    <Card className="p-5" data-testid="brain-pages-links">
      <p className="max-w-[70ch] text-pretty text-[13.5px] text-ink-2">
        At <span className="font-mono text-[13px] text-ink">{b.pagesUrl}</span>. Each button opens a new tab and signs you in with
        a link that works once. Pages opens first; Lately, Ask, Import and Export are one click away there.
      </p>
      <div className="mt-3 flex flex-wrap gap-2">
        <Button size="sm" variant="outline" disabled={!on} onClick={() => openBrainPage("pages")} data-testid="brain-open-pages">
          <ExternalLink className="h-3.5 w-3.5" /> Pages
        </Button>
        <Button size="sm" variant="outline" disabled={!on} onClick={() => openBrainPage("admin")} data-testid="brain-open-admin">
          <ExternalLink className="h-3.5 w-3.5" /> GBrain admin
        </Button>
      </div>
      {!on ? <p className="mt-3 text-[13px] text-ink-2">They open while the brain is running.</p> : null}
    </Card>
  );
}

/** The pages need a name the browser reaches with HTTPS before they can open (docs/standalone/brain.md). */
function PagesName({ onChanged }: { onChanged: () => void }) {
  const [name, setName] = useState("");
  const save = useMutation({
    mutationFn: (hostname: string) => brainSource.setPagesName({ hostname }),
    onSuccess: (r) => {
      toast.success(`The brain’s pages are at ${r.url}`);
      onChanged();
    },
  });
  const submit = (e: FormEvent) => {
    e.preventDefault();
    const host = pagesHostname(name);
    if (host) save.mutate(host);
  };
  return (
    <Card className="p-5" data-testid="brain-pages-name">
      <p className="max-w-[70ch] text-pretty text-[13.5px] text-ink-2">
        To open them from here, give them a name your browser reaches with HTTPS, such as <span className="font-mono text-[13px]">brain.example.com</span>.
        Put HTTPS for that name in front of the firewall’s <span className="font-mono text-[13px]">BRAIN_PAGES_BIND</span> (
        <span className="font-mono text-[13px]">127.0.0.1:8803</span> by default), for example with Caddy. It must be the name
        the brain was installed with. You set it once: to change it, pair the brain again.
      </p>
      <form onSubmit={submit} className="mt-3 flex flex-wrap gap-2">
        <Input
          value={name}
          onChange={(e) => setName(e.target.value)}
          placeholder="brain.example.com"
          aria-label="Name of the brain’s pages"
          className="h-9 w-full max-w-[320px]"
          data-testid="brain-pages-hostname"
        />
        <Button type="submit" size="sm" className="h-9" disabled={!name.trim() || save.isPending} data-testid="brain-pages-save">
          Save
        </Button>
      </form>
      {save.error ? (
        <div className="mt-3">
          <FormError>{errorText(save.error)}</FormError>
        </div>
      ) : null}
    </Card>
  );
}

/** The admin's lock: every agent off the brain at once, connections kept. */
function LockCard({ brain: b, onChanged }: { brain: Brain; onChanged: () => void }) {
  const lock = useMutation({
    mutationFn: (locked: boolean) => brainSource.setLock({ locked }),
    onSuccess: (_, locked) => {
      toast.success(locked ? "The brain is locked." : "The brain is unlocked.");
      onChanged();
    },
  });
  return (
    <Card className="p-5" data-testid="brain-lock">
      <p className="max-w-[70ch] text-pretty text-[13.5px] text-ink-2">
        {b.lockedByAdmin
          ? "Locked: no agent can search the brain or save to it. Their connections are kept, so unlocking lets them back."
          : "Locking keeps every agent out of the brain at once. Their connections are kept, so unlocking lets them back without turning each one on again."}
        {b.stoppedAll ? (
          <>
            {" "}
            The emergency stop also keeps them out until you press Start again on its banner.
          </>
        ) : null}
      </p>
      <Button
        size="sm"
        variant="outline"
        className="mt-3"
        disabled={lock.isPending}
        onClick={() => lock.mutate(!b.lockedByAdmin)}
        data-testid="brain-lock-toggle"
      >
        {b.lockedByAdmin ? <Unlock className="h-3.5 w-3.5" /> : <Lock className="h-3.5 w-3.5" />}
        {b.lockedByAdmin ? "Unlock" : "Lock the brain"}
      </Button>
      {lock.error ? (
        <div className="mt-3">
          <FormError>{errorText(lock.error)}</FormError>
        </div>
      ) : null}
    </Card>
  );
}

/**
 * The brain's pages under Brain in the sidebar, while it runs and they have a name. It opens a new
 * tab, signed in, on Pages, where Lately, Ask, Import and Export are one click away (the sign-in
 * link lands nowhere else). Not on a phone, where the sidebar is one scrolling row: the Brain page
 * has the button.
 */
export function BrainNavPages() {
  const q = useQuery(brainQuery);
  const b = q.data?.brain;
  if (!b?.pages || !running(b)) return null;
  return (
    <div className="ml-[19px] hidden flex-col border-l border-line pl-2 md:flex" data-testid="brain-nav-pages">
      <button
        type="button"
        onClick={() => openBrainPage("pages")}
        className="flex items-center justify-between gap-2 rounded-lg px-[10px] py-1.5 text-left text-[13px] text-ink-2 hover:bg-bg"
        title="Pages, Lately, Ask, Import and Export, in a new tab"
        data-testid="brain-nav-pages-open"
      >
        Its pages
        <ExternalLink className="h-3 w-3 opacity-60" aria-hidden="true" />
      </button>
    </div>
  );
}
