/** The software, update and ansible source shapes an agent or firewall box reports, as the console stores them. */

/**
 * How far a firewall box has got through re-provisioning itself
 * (apps/saas/docs/features/firewall.md).
 */
export type VmUpdateProgress = {
  reboot?: boolean;
  phase: "idle" | "resolving" | "installing" | "running" | "done" | "failed";
  detail: string | null;
  /** The commit the box pinned itself to, once it has resolved one. */
  ref: string | null;
  at: string | null;
};

/**
 * What a box last said it is running (`apps/saas/docs/features/agent-settings.md`).
 *
 * Reported by both daemons — the vm-agent on `/ready` and `/status`, the mitm-agent on `/ready`
 * and every heartbeat — and parsed with zod before it lands here (`app/(vm)/lib/software.schema.ts`).
 * Every string is the box's word, so it is display text and nothing else: never parsed into a
 * decision, never compared against anything the control plane holds.
 *
 * All three parts are independently nullable because they go missing independently: a box built
 * before this existed sends nothing at all, a box provisioned before the release file existed
 * sends `release: null`, and a firewall box has no `openclaw` because it runs none.
 */
export type VmSoftware = {
  rebootRequired?: boolean;
  bootedAt?: string;
  /** The daemon's own build: its package version, the commit of this repo it was built from, and when. */
  agent: { version: string; commit: string; builtAt: string } | null;
  /**
   * The Ansible release installed on the box. `version` ("1.4.0") is the newest entry of the
   * checkout's releases.json; boxes provisioned before that existed send no version.
   */
  release: { commit: string; commitDate: string; installedAt: string; version?: string } | null;
  /** The OpenClaw version on an agent box; null on a firewall and when it could not be read. */
  openclaw: string | null;
  /**
   * What an agent box says it can do (browser-enrollment.md §10): `open_v1` once it takes
   * firewall-issued tickets and knows where its firewall is. Absent on older boxes.
   */
  features?: string[];
};

/**
 * Where this box's Ansible came from, as `resolveAnsibleSource` decided it at provisioning.
 *
 * A secured box reads `https://github.com/madarco/controlclaw-ansible.git` on `main` and needs no
 * explanation. It is here for the third mode: a DEV-SECURED pair is a full pair — encrypted disk,
 * mitm routing, on-box keys — built from a branch of the public test repo so a box can try
 * unmerged vm-agent / mitm-agent code on real hardware. That is not a production guarantee, and
 * the console says which branch it is rather than making someone read an env var to find out.
 *
 * Null on every box provisioned before this column existed.
 */
export type VmAnsibleSource = {
  repoUrl: string;
  branch: string;
  /**
   * Whether this box was built with the 24h aged-commit rule relaxed to plain branch HEAD
   * (`ANSIBLE_UPDATE_ALLOW_UNVERIFIED`). Recorded here because the flag is read once, at
   * provisioning, and cannot be changed on a running box — so the control plane's *current*
   * setting is not what this box obeys. The console needs the box's own rule to tell it whether an
   * update is available; without this it would apply today's flag to a box built under the other
   * one. Absent on rows written before it was recorded.
   */
  allowUnverified?: boolean;
};
