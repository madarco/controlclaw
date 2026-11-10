import type { Facts } from "../doctor.js";
import type { FirewallNet } from "./docker.js";
import type { Install } from "../openclaw.js";
import type { Check } from "../probe.js";
import type { ConnectRecord, Firewall, Recorder } from "../state.js";
import type { Sys, User } from "../sys.js";

/** What every capture mode gets from `connect`. */
export interface Ctx {
  sys: Sys;
  rec: Recorder;
  facts: Facts;
  install: Install;
  user: User | null;
  firewall: Firewall;
  /** The CA as PEM, and where `connect` put it for OpenClaw to read. */
  caPem: string;
  caPath: string;
  log: (line: string) => void;
  /** Remote mode: the tunnel pairing gave, and this machine's WireGuard private key. */
  tunnel?: Tunnel;
  /** `controlclaw up`, docker mode: the gateway joins the firewall container's own network. */
  firewallNet?: FirewallNet;
}

export interface Tunnel {
  /** This machine's tunnel address. */
  address: string;
  /** The firewall's: its proxy and DNS answer there. */
  firewall: string;
  firewallPublicKey: string;
  endpoint: string;
  privateKey: string;
}

export interface CaptureMode {
  name: string;
  /** One line from plan §4: how much this mode protects. */
  protects: string;
  /** Why this machine cannot do it; empty when it can. */
  blockers(facts: Facts): string[];
  /** Before the vm-agent is installed (remote mode: the tunnel it listens on). */
  prepare?(ctx: Ctx): Promise<void>;
  /** Puts the capture in place. Returns notes for the owner. */
  install(ctx: Ctx): Promise<string[]>;
  status(sys: Sys, record: ConnectRecord): Promise<Check[]>;
}
