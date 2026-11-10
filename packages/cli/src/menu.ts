import { closeSync, openSync } from "node:fs";
import { createInterface, emitKeypressEvents } from "node:readline";
import { ReadStream } from "node:tty";

/**
 * `controlclaw up`'s menu: arrow keys on a terminal; a numbered prompt when stdin is not one but the
 * machine has a terminal (`/dev/tty`, as with `curl … | sh`); none at all, and `up` asks for a flag.
 */
export interface MenuItem {
  label: string;
  hint: string;
}

/** The person's pick and typed lines, swapped in tests. */
export interface Ask {
  /** The index picked, or null when there is no terminal to ask on (or it was left with Ctrl+C). */
  pick: (title: string, items: MenuItem[]) => Promise<number | null>;
  /** A line typed, shown as typed; null without a terminal. */
  line: (prompt: string) => Promise<string | null>;
}

const W = process.stderr;
const bold = (s: string) => (W.isTTY ? `\x1b[1m${s}\x1b[0m` : s);
const dim = (s: string) => (W.isTTY ? `\x1b[2m${s}\x1b[0m` : s);

/** The rows of the menu, the chosen one marked. */
export function renderMenu(title: string, items: MenuItem[], at: number): string[] {
  const width = Math.max(...items.map((i) => i.label.length));
  return [`? ${bold(title)}`, ...items.map((it, i) => `${i === at ? "❯" : " "} ${(i === at ? bold : (s: string) => s)(it.label.padEnd(width))}  ${dim(it.hint)}`)];
}

/** A terminal to ask on: stdin when it is one, else /dev/tty; null when there is none. */
function terminal(): { input: NodeJS.ReadableStream & { setRawMode?: (b: boolean) => void; isTTY?: boolean }; close: () => void } | null {
  if (process.stdin.isTTY) return { input: process.stdin, close: () => {} };
  try {
    const fd = openSync("/dev/tty", "r");
    const s = new ReadStream(fd);
    return { input: s, close: () => {
      s.destroy();
      try {
        closeSync(fd);
      } catch {
        /* closed with the stream */
      }
    } };
  } catch {
    return null;
  }
}

async function arrowPick(title: string, items: MenuItem[], input: NodeJS.ReadStream): Promise<number | null> {
  let at = 0;
  const draw = (again: boolean) => {
    if (again) W.write(`\x1b[${items.length + 1}A`);
    for (const l of renderMenu(title, items, at)) W.write(`\x1b[2K${l}\n`);
  };
  emitKeypressEvents(input);
  input.setRawMode(true);
  input.resume();
  draw(false);
  return new Promise((resolve) => {
    const done = (v: number | null) => {
      input.off("keypress", onKey);
      input.setRawMode(false);
      input.pause();
      resolve(v);
    };
    const onKey = (_: string, k: { name?: string; ctrl?: boolean }) => {
      if (k.ctrl && k.name === "c") return done(null);
      if (k.name === "up" || k.name === "k") at = (at + items.length - 1) % items.length;
      else if (k.name === "down" || k.name === "j") at = (at + 1) % items.length;
      else if (k.name === "return") return done(at);
      else return;
      draw(true);
    };
    input.on("keypress", onKey);
  });
}

async function numberedPick(title: string, items: MenuItem[], input: NodeJS.ReadableStream): Promise<number | null> {
  W.write(`${title}\n`);
  items.forEach((it, i) => W.write(`  ${i + 1}. ${it.label} - ${it.hint}\n`));
  for (;;) {
    const a = await readLine(input, `Choose 1-${items.length}: `);
    if (a === null) return null;
    const n = Number(a.trim());
    if (Number.isInteger(n) && n >= 1 && n <= items.length) return n - 1;
  }
}

function readLine(input: NodeJS.ReadableStream, prompt: string): Promise<string | null> {
  return new Promise((resolve) => {
    const rl = createInterface({ input, output: W, terminal: false });
    W.write(prompt);
    let got = false;
    rl.once("line", (l) => {
      got = true;
      rl.close();
      resolve(l);
    });
    rl.once("close", () => {
      if (!got) resolve(null);
    });
  });
}

export const terminalAsk: Ask = {
  async pick(title, items) {
    const t = terminal();
    if (!t) return null;
    try {
      const raw = t.input as NodeJS.ReadStream;
      return raw.isTTY && typeof raw.setRawMode === "function" && process.stdin.isTTY ? await arrowPick(title, items, raw) : await numberedPick(title, items, t.input);
    } finally {
      t.close();
    }
  },
  async line(prompt) {
    const t = terminal();
    if (!t) return null;
    try {
      return await readLine(t.input, prompt);
    } finally {
      t.close();
    }
  },
};
