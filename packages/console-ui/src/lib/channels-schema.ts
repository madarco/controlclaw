import { z } from "zod";
import type {
  AgentChannelBoxStatus,
  AgentChannelChangeKind,
  AgentChannelChangeStatus,
  AgentChannelMode,
  AgentChannelState,
  AgentChannelType,
  BoxRead,
} from "./channel-states";

export const agentChannelTypeSchema = z.enum(["telegram", "slack", "whatsapp"]);

/**
 * Display metadata for the cards. iMessage is listed so people see it is coming. Team chat
 * (`clickclack`) is `automatic`: nobody connects it, the firewall puts every agent in it when the
 * organization turns it on, so it is not an `agent_channel_type` and has no connection rows.
 */
export const CHANNEL_CATALOG: ReadonlyArray<{
  type: AgentChannelType | "imessage" | "clickclack";
  name: string;
  blurb: string;
  available: boolean;
  automatic?: boolean;
}> = [
  { type: "telegram", name: "Telegram", blurb: "A bot from @BotFather. People message the bot.", available: true },
  { type: "whatsapp", name: "WhatsApp", blurb: "A number linked by scanning a QR code with your phone.", available: true },
  { type: "slack", name: "Slack", blurb: "A Slack app in Socket Mode, added to your workspace.", available: true },
  { type: "imessage", name: "iMessage", blurb: "Needs a Mac running BlueBubbles. Coming later.", available: false },
  { type: "clickclack", name: "Team chat", blurb: "A chat room on your firewall. Every agent joins it automatically.", available: true, automatic: true },
];

export function channelName(type: AgentChannelType): string {
  return CHANNEL_CATALOG.find((c) => c.type === type)?.name ?? type;
}

/** How long a confirmation code is valid, and how many tries the person gets. Mirrored on the firewall. */
export const CHANNEL_CODE_TTL_MS = 10 * 60_000;
export const CHANNEL_CODE_ATTEMPTS = 5;
/** A queued change the firewall never picked up within this window is shown as stuck. */
export const CHANNEL_CHANGE_STUCK_MS = 2 * 60_000;

const token = z.string().trim().min(8).max(512);
const label = z.string().trim().max(80).optional();

// ---- inputs ----

/** Connect a bot or a Slack app for the organization, optionally live on an agent right away. */
export const addConnectionSchema = z.object({
  type: z.enum(["telegram", "slack"]),
  botToken: token,
  appToken: token.optional(),
  label,
  /** The agent to enable it on at once. Left out, the connection waits in the organization. */
  vmId: z.string().min(1).optional(),
});
export type AddConnectionInput = z.infer<typeof addConnectionSchema>;

export const replaceSecretSchema = z.object({
  connectionId: z.string().min(1),
  botToken: token,
  appToken: token.optional(),
  label,
});
export type ReplaceSecretInput = z.infer<typeof replaceSecretSchema>;

export const connectionIdSchema = z.object({ connectionId: z.string().min(1) });
export const assignSchema = z.object({ connectionId: z.string().min(1), vmId: z.string().min(1) });
export const unassignSchema = connectionIdSchema;

export const approvePairingSchema = z.object({
  connectionId: z.string().min(1),
  code: z.string().trim().min(4).max(16),
  senderId: z.string().trim().min(1).max(128),
  label: z.string().trim().max(120).optional(),
});

/** Link (or re-link) a WhatsApp number on an agent. The session lives on that box. */
export const whatsappLoginSchema = z.object({
  vmId: z.string().min(1),
  /** Left out on a move: the number keeps what it was linked as. */
  personal: z.boolean().optional(),
  /** Re-link an existing connection instead of creating one. */
  connectionId: z.string().min(1).optional(),
});
export type WhatsappLoginInput = z.infer<typeof whatsappLoginSchema>;

export const confirmChannelChangeSchema = z.object({
  changeId: z.string().min(1),
  code: z
    .string()
    .trim()
    .transform((s) => s.replace(/\s+/g, ""))
    .pipe(z.string().regex(/^\d{6}$/, "The code is 6 digits")),
});

/** Add somebody to, or take somebody off, the list that gets confirmation codes (T-83). */
export const codeRecipientSchema = z.object({
  connectionId: z.string().min(1),
  senderId: z.string().trim().min(1).max(128),
  label: z.string().trim().max(120).optional(),
});
export type CodeRecipientInput = z.infer<typeof codeRecipientSchema>;

export const changeIdSchema = z.object({ changeId: z.string().min(1) });
export const vmIdSchema = z.object({ vmId: z.string().min(1) });
/**
 * `readBox: false` answers from the database alone, every box `deferred`. The Channels page polls
 * that way and reads each agent's box on its own with `channels.readAgentBox`, so one quiet box
 * does not hold the rest.
 */
export const listConnectionsSchema = z.object({ readBox: z.boolean().optional() }).optional();

// ---- views ----

export type AgentRefView = { vmId: string; name: string; displayName: string | null; status: string };

/** One channel connection of the organization as the console shows it. */
export type ConnectionView = {
  id: string;
  type: AgentChannelType;
  label: string | null;
  secretHint: string | null;
  state: AgentChannelState;
  mode: AgentChannelMode;
  /** The agent it is live on, or null while it waits in the organization. */
  assignedVm: AgentRefView | null;
  boxStatus: AgentChannelBoxStatus | null;
  lastError: string | null;
  updatedAt: string;
};

export type AgentChannelChangeView = {
  id: string;
  connectionId: string | null;
  vmId: string | null;
  channelType: AgentChannelType;
  kind: AgentChannelChangeKind;
  summary: string;
  status: AgentChannelChangeStatus;
  tofu: boolean;
  sentVia: string | null;
  attemptsLeft: number | null;
  expiresAt: string | null;
  error: string | null;
  createdAt: string;
  /** Queued for longer than CHANNEL_CHANGE_STUCK_MS without the firewall picking it up. */
  stuck: boolean;
};

/** A sender waiting for approval, read live from the box the connection is assigned to. */
export type PendingPairingView = {
  type: AgentChannelType;
  code: string;
  senderId: string;
  label: string | null;
  createdAt: string | null;
  /** The connection the request arrived on, when one of that type is assigned to the box. */
  connectionId: string | null;
};

/** `installing`: the box is fetching the WhatsApp plugin, so there is no QR code to show yet. */
export type WhatsappLoginState = "idle" | "installing" | "qr" | "connected" | "failed" | "expired";

/** One channel as the box reports it right now (no `at`: it is live). */
export type LiveChannelStatus = Omit<AgentChannelBoxStatus, "at"> & { label?: string | null };

/**
 * Why the box could not say who is waiting. `busy` means OpenClaw was restarting or its state was
 * held — worth another look in a moment — as against a command that actually failed.
 */
export type PairingsErrorView = { busy: boolean; message: string };

/** Live read from the agent box (`GET /channels/status`), or why there is none. */
export type AgentChannelsLive = {
  /** `deferred` until somebody has actually asked the box — see `BoxRead`. */
  boxRead: BoxRead;
  status: Partial<Record<AgentChannelType, LiveChannelStatus>>;
  pairings: PendingPairingView[];
  /** Set when the pending-pairing listing came back short rather than empty. */
  pairingsError: PairingsErrorView | null;
  /**
   * `onBox`: the box shows the QR on its own page (`whatsapp_page`, browser-enrollment.md §7), so the
   * image never reaches the control plane and the console offers a link to that page instead.
   */
  whatsappLogin: { state: WhatsappLoginState; qrDataUrl: string | null; message: string | null; onBox?: boolean } | null;
};

/** `/dashboard/inbound`: every connection of the organization and where it is. */
export type ConnectionsView = {
  canManage: boolean;
  firewall: { state: "none" | "starting" | "active" | "inactive"; reachable: boolean };
  connections: ConnectionView[];
  /** The org's agents and the connections on each, for the overview and the assign pickers. */
  agents: Array<AgentRefView & { connections: Array<{ id: string; type: AgentChannelType; label: string | null }> }>;
  /** Senders waiting for approval, read from the boxes that have a connection assigned. */
  pairings: PendingPairingView[];
  /** Set when one of those boxes could not be asked; the pairing list is short, not empty. */
  pairingsError: PairingsErrorView | null;
  /** A WhatsApp link in progress, per agent, so the QR can be shown from this page too. */
  whatsappLogins: Record<string, NonNullable<AgentChannelsLive["whatsappLogin"]>>;
  /**
   * Per agent that carries a connection, keyed by vmId: whether its box has been read. The server
   * render leaves running ones `deferred`; the panel reads each box on its own and fills this in
   * (`app/(channels)/lib/connections-live.ts`).
   */
  boxReads: Record<string, AgentBoxReadState>;
  pending: AgentChannelChangeView | null;
  recent: AgentChannelChangeView[];
};

/** How far the Channels page got with one agent's box, and what it said about who is waiting. */
export type AgentBoxReadState = { boxRead: BoxRead; pairingsError: PairingsErrorView | null };

/**
 * "Who gets confirmation codes" on the Firewall page (T-83).
 *
 * `approved` is the firewall's own list: these people, and nobody else, are sent a six-digit code
 * when something needs confirming. `allowed` is what the agent boxes read out of OpenClaw's own DM
 * allow list — people who can already talk to the agent but whom nobody has confirmed. They are
 * kept apart on purpose: an agent box is untrusted, so a compromised agent could put an attacker
 * in that list, and adding one is itself a firewall change under the normal consent rule.
 *
 * `allowed: null` means the firewall has not managed to read a box, which is NOT the same as there
 * being nobody to add — the empty state says so.
 */
export type CodeRecipientView = {
  connectionId: string;
  type: AgentChannelType;
  /** The connection the sender can talk to, e.g. "@moma_fambot". */
  connectionLabel: string | null;
  senderId: string;
  /** OpenClaw's own name for them, when it has one. Never invented, so this is often null. */
  senderLabel: string | null;
  at: string | null;
  vmId: string | null;
  agentName: string | null;
};

export type CodeRecipientsView = {
  canManage: boolean;
  firewall: { state: "none" | "starting" | "active" | "inactive"; reachable: boolean };
  /** False on a firewall that has never reported this — one built before the feature. */
  reported: boolean;
  approved: CodeRecipientView[];
  allowed: CodeRecipientView[] | null;
  /** Why `allowed` is short, when a box could not be read. */
  allowedError: { busy: boolean; message: string } | null;
  /** When the firewall last reported all this. */
  at: string | null;
  /** A change of THIS card's kinds, if one is in flight. */
  pending: AgentChannelChangeView | null;
  /**
   * Some other channel change has the organization's single change slot — a token being connected
   * on the Channels page, say. Nothing here can be started until it finishes, and the card says so
   * rather than offering buttons the server can only answer CONFLICT.
   */
  busyElsewhere: boolean;
  recent: AgentChannelChangeView[];
};

/** `/dashboard/agents/<id>/channels`: what this agent listens on. */
export type AgentChannelsView = {
  vm: AgentRefView;
  canManage: boolean;
  firewall: { state: "none" | "starting" | "active" | "inactive"; reachable: boolean };
  /** Connections live on this agent. */
  assigned: ConnectionView[];
  /** Unassigned Telegram and Slack connections of the org, ready to be enabled here. */
  available: ConnectionView[];
  pending: AgentChannelChangeView | null;
  recent: AgentChannelChangeView[];
  live: AgentChannelsLive;
  /**
   * Team chat on this agent, when the organization has it on: the firewall's report for this agent,
   * or `status: null` before it has said anything. Null when Team chat is off. Optional so older
   * fixtures stay valid.
   */
  teamChat?: { status: "connecting" | "connected" | "failed" | "removing" | null; error: string | null } | null;
};
