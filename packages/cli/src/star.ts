import { join } from "node:path";
import type { Io } from "./commands.js";
import type { Ask } from "./menu.js";
import { type Sys, type User, userByName, userByUid } from "./sys.js";

/**
 * After a good `up`, one question: star the repo on GitHub? Asked on at most two runs, and never
 * again once answered. With `gh` signed in, a yes stars it; otherwise the URL is printed (no browser
 * is opened: `up` often runs over SSH). Nothing here can fail `up`.
 *
 * The answer is the person's, not the machine's: it is kept in their XDG state folder, not in
 * stateDir, which uninstall removes when it is empty. Under sudo, the person is SUDO_USER: gh runs
 * as them, with their sign-in, and the file is theirs.
 */
export const STAR_REPO = "madarco/controlclaw";
export const STAR_URL = `https://github.com/${STAR_REPO}`;
/** `up` runs it is asked on, at most. */
const MAX_ASKED = 2;

export interface StarState {
  version: 1;
  asked: number;
  answered: boolean;
  starred: boolean;
}

/** Who answers: SUDO_USER under sudo; null for the user running it. */
function person(sys: Sys): User | null {
  return sys.euid === 0 && sys.env.SUDO_USER ? userByName(sys, sys.env.SUDO_USER) : null;
}

export function starStatePath(sys: Sys, who: User | null = person(sys)): string {
  const home = who?.home ?? (sys.euid === 0 ? (userByUid(sys, 0)?.home ?? "/root") : (sys.env.HOME ?? "/tmp"));
  const base = (!who && sys.env.XDG_STATE_HOME) || join(home, ".local", "state");
  return join(base, "controlclaw", "star-prompt.json");
}

async function loadStarState(sys: Sys, who: User | null): Promise<StarState> {
  try {
    const path = starStatePath(sys, who);
    const s = JSON.parse((who ? await sys.readAs(who, path) : sys.read(path)) ?? "") as Partial<StarState>;
    if (s.version === 1) return { version: 1, asked: Number(s.asked) || 0, answered: s.answered === true, starred: s.starred === true };
  } catch {
    /* none yet, or unreadable: start over */
  }
  return { version: 1, asked: 0, answered: false, starred: false };
}

async function saveStarState(sys: Sys, who: User | null, s: StarState): Promise<void> {
  const path = starStatePath(sys, who);
  const data = `${JSON.stringify(s, null, 2)}\n`;
  if (who) await sys.writeAs(who, path, data, 0o644);
  else sys.write(path, data);
}

/** Yes, no, or null for an answer that is neither. Empty is yes. */
function yesNo(line: string): boolean | null {
  const a = line.trim().toLowerCase();
  if (a === "" || a === "y" || a === "yes") return true;
  if (a === "n" || a === "no") return false;
  return null;
}

/** Whether the person is at a terminal: stdin and stdout both, and not in CI. */
export function interactive(sys: Sys): boolean {
  return process.stdin.isTTY === true && process.stdout.isTTY === true && !sys.env.CI;
}

/** The question, when it is due. `tty`: whether there is a person to ask (swapped in tests). */
export async function starPrompt(sys: Sys, io: Io, ask: Ask, tty: boolean = interactive(sys)): Promise<void> {
  if (!tty) return;
  try {
    const who = person(sys);
    const user = who ?? undefined;
    const state = await loadStarState(sys, who);
    if (state.answered || state.asked >= MAX_ASKED) return;
    state.asked += 1;
    await saveStarState(sys, who, state);
    let yes: boolean | null = null;
    while (yes === null) {
      const line = await ask.line("Help support this open source project. Would you like to star it on GitHub? [Y/n] ");
      // No terminal after all (stdin closed): not an answer.
      if (line === null) return;
      yes = yesNo(line);
    }
    state.answered = true;
    await saveStarState(sys, who, state);
    if (!yes) return;
    const gh = await sys.run(["gh", "auth", "status", "--hostname", "github.com"], { user, timeoutMs: 15_000 });
    if (gh.code === 0) {
      const r = await sys.run(["gh", "api", "--method", "PUT", `/user/starred/${STAR_REPO}`], { user, timeoutMs: 30_000 });
      if (r.code === 0) {
        state.starred = true;
        await saveStarState(sys, who, state);
        io.out(`Starred ${STAR_REPO}. Thank you!`);
        return;
      }
    }
    io.out(`Star it at ${STAR_URL}`);
  } catch {
    io.out(`Star it anytime at ${STAR_URL}`);
  }
}
