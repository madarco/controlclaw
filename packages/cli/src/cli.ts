import { createInterface } from "node:readline";
import { parseArgs } from "node:util";
import { connect, disconnect, doctor, type Io, realNet, status } from "./commands.js";
import { type Ask, terminalAsk } from "./menu.js";
import { open } from "./open.js";
import { openclawInstall } from "./openclaw-install.js";
import { connectHere, type HereNet, installFirewall, uninstall, upAll, upHere } from "./up.js";
import { realSys, type Sys } from "./sys.js";

declare const __CC_CLI_VERSION__: string;
const VERSION = typeof __CC_CLI_VERSION__ === "string" ? __CC_CLI_VERSION__ : "0.0.0-dev";

export const USAGE = `controlclaw ${VERSION}

  Put OpenClaw behind a ControlClaw firewall: the firewall, OpenClaw, and the connection between them.

  controlclaw up [--all | --here]
      A menu of the ways to set it up, run in order. --all: the firewall and a new OpenClaw here
      (install, openclaw install, connect: two containers, the strongest). --here: the firewall next
      to the OpenClaw already here (install, then connect). up --local is up --all.

  controlclaw install [--docker | --host] [--listen <private ip>] [--firewall-image <image>]
      The firewall on this machine: a container (default), or install.sh's systemd units (--host).
      --listen: also for OpenClaw on other machines of your network, at that address. Opens the panel.

  controlclaw openclaw install [--docker | --host] [--firewall <url>]
      A new OpenClaw here: in Docker (default) or with OpenClaw's own installer as its own user
      (--host). Then connects it: to --firewall, or to the firewall installed here.

  controlclaw connect [--mode auto|docker|host|proxy|remote] [--firewall <url>] [--capture-only]
                      [--code - | --code-file <file>] [--name <agent name>] [--user <name>] [--vm-agent <path>]
      This machine's OpenClaw behind a firewall: the vm-agent and the capture for the mode (auto: docker
      for an OpenClaw in a container, else host). Without --firewall, the firewall installed here, paired
      with no code. With --firewall (its pairing address, such as http://10.0.0.2:8801), a one-time
      code from its panel, asked for (--code - reads stdin; --code <code> is refused: others can read it).
      --capture-only: the traffic only, no vm-agent (the panel cannot set models or bots here).

  controlclaw connect --mode ... --firewall <url> --ca <file> [--firewall-key <pem>] ...
      The same without pairing: the firewall's CA and key by hand.

  controlclaw open
      Opens the panel of the firewall on this machine; before the first sign-in, with its setup token.

  controlclaw status [--json]
      Whether the firewall here, the capture and the vm-agent are up.

  controlclaw disconnect [--restore-config] [--force]
      Undo connect. --restore-config also puts back OpenClaw's config as it was before connect.

  controlclaw uninstall [--purge] [--force]
      disconnect, then remove the firewall installed here. Its data (rules, password, CA) only with --purge.

  controlclaw doctor [--json]
      What this machine has, which modes it can do, and how much each protects.

  Host mode and install --host need root (sudo). Docker mode needs a user who can use Docker (the
  docker group, which can do what root does). Proxy mode works without either.
`;

/** `up`'s menu: what each choice runs. */
export const UP_CHOICES = [
  { id: "all", label: "Firewall + new OpenClaw here", hint: "Two containers, OpenClaw's only way out is the firewall. Strongest." },
  { id: "here", label: "Protect the OpenClaw here", hint: "Keeps your install. The firewall runs next to it." },
  { id: "firewall", label: "Firewall only", hint: "For OpenClaw on other machines. They run `controlclaw connect`." },
  { id: "openclaw", label: "New OpenClaw only", hint: "Behind a firewall on another machine." },
  { id: "connect", label: "Connect this OpenClaw", hint: "To a firewall on another machine." },
] as const;

/** Runs a command; `ask` is the menu's (swapped in tests). */
export async function run(argv: string[], io: Io, sys: Sys = realSys(), ask: Ask = terminalAsk, net: HereNet = realNet): Promise<number> {
  let [command, ...rest] = argv;
  // `openclaw install`: one command of two words.
  if (command === "openclaw") {
    if (rest[0] !== "install") {
      io.err("controlclaw openclaw install [--docker | --host] [--firewall <url>]");
      return 2;
    }
    command = "openclaw install";
    rest = rest.slice(1);
  }
  let values: Record<string, string | boolean | undefined>;
  try {
    ({ values } = parseArgs({
      args: rest,
      strict: true,
      options: {
        json: { type: "boolean" },
        force: { type: "boolean" },
        mode: { type: "string" },
        firewall: { type: "string" },
        ca: { type: "string" },
        "firewall-key": { type: "string" },
        proxy: { type: "string" },
        dns: { type: "string" },
        user: { type: "string" },
        "vm-agent": { type: "string" },
        code: { type: "string" },
        "code-file": { type: "string" },
        name: { type: "string" },
        local: { type: "boolean" },
        all: { type: "boolean" },
        here: { type: "boolean" },
        docker: { type: "boolean" },
        host: { type: "boolean" },
        listen: { type: "string" },
        purge: { type: "boolean" },
        "restore-config": { type: "boolean" },
        "capture-only": { type: "boolean" },
        "firewall-image": { type: "string" },
        "openclaw-image": { type: "string" },
        dir: { type: "string" },
      },
    }));
  } catch (e) {
    io.err((e as Error).message);
    return 2;
  }
  const s = (k: string) => (typeof values[k] === "string" ? (values[k] as string) : undefined);
  const b = (k: string) => values[k] === true;
  if (b("docker") && b("host")) {
    io.err("--docker or --host, not both.");
    return 2;
  }
  switch (command) {
    case "doctor":
      return doctor(sys, io, { json: b("json"), user: s("user"), vmAgent: s("vm-agent") });
    case "install":
      return installFirewall(sys, io, { host: b("host"), listen: s("listen"), firewallImage: s("firewall-image"), name: s("name") }, net);
    case "openclaw install":
      return openclawInstall(sys, io, { host: b("host"), firewall: s("firewall"), openclawImage: s("openclaw-image"), dir: s("dir"), name: s("name"), vmAgent: s("vm-agent"), user: s("user") }, net);
    case "connect":
      if (!s("firewall")) {
        if (s("ca") || s("code") || s("code-file") || s("proxy") || s("dns")) {
          io.err("--ca, --code, --proxy and --dns go with --firewall <url>. Without it, connect pairs with the firewall on this machine by itself.");
          return 2;
        }
        return connectHere(sys, io, { mode: s("mode"), name: s("name"), user: s("user"), vmAgent: s("vm-agent"), captureOnly: b("capture-only") }, net);
      }
      return connect(sys, io, {
        mode: s("mode"),
        firewall: s("firewall"),
        ca: s("ca"),
        firewallKey: s("firewall-key"),
        proxy: s("proxy"),
        dns: s("dns"),
        user: s("user"),
        vmAgent: s("vm-agent"),
        code: s("code"),
        codeFile: s("code-file"),
        name: s("name"),
        captureOnly: b("capture-only"),
      }, net);
    case "up": {
      const picked = [b("all") || b("local"), b("here")].filter(Boolean).length;
      if (picked > 1) {
        io.err("up --all or up --here, not both.");
        return 2;
      }
      if (!picked) return upMenu(sys, io, ask, net, { firewallImage: s("firewall-image"), name: s("name"), vmAgent: s("vm-agent") });
      if (b("here")) return upHere(sys, io, { mode: s("mode"), firewallImage: s("firewall-image"), name: s("name"), user: s("user"), vmAgent: s("vm-agent"), listen: s("listen") }, net);
      if (s("mode")) {
        io.err("up --all starts its own OpenClaw in Docker: leave out --mode.");
        return 2;
      }
      return upAll(sys, io, { firewallImage: s("firewall-image"), openclawImage: s("openclaw-image"), dir: s("dir"), name: s("name"), vmAgent: s("vm-agent") }, net);
    }
    case "disconnect":
      return disconnect(sys, io, { force: b("force"), restoreConfig: b("restore-config") }, net.post);
    case "uninstall":
      return uninstall(sys, io, { purge: b("purge"), force: b("force") }, net.post);
    case "status":
      return status(sys, io, { json: b("json") });
    case "open":
      return open(sys, io, net.open);
    case "--version":
    case "version":
      io.out(VERSION);
      return 0;
    case undefined:
    case "help":
    case "--help":
    case "-h":
      io.out(USAGE);
      return command === undefined ? 2 : 0;
    default:
      io.err(`Unknown command: ${command}\n`);
      io.err(USAGE);
      return 2;
  }
}

/** `up` with no flag: the menu, then what was picked. Without a terminal, it asks for a flag. */
async function upMenu(sys: Sys, io: Io, ask: Ask, net: HereNet, o: { firewallImage?: string; name?: string; vmAgent?: string }): Promise<number> {
  const at = await ask.pick("What do you want to set up?", UP_CHOICES.map((c) => ({ label: c.label, hint: c.hint })));
  if (at === null) {
    io.err("No terminal to show the menu on: run up --all (the firewall and a new OpenClaw here), up --here (the firewall next to the OpenClaw here), or the commands themselves (controlclaw --help).");
    return 2;
  }
  const askUrl = async (): Promise<string | null> => {
    const u = (await ask.line("The firewall's pairing address (such as http://10.0.0.2:8801): "))?.trim();
    if (!u) io.err("No address: nothing was done.");
    return u || null;
  };
  switch (UP_CHOICES[at]!.id) {
    case "all":
      return upAll(sys, io, o, net);
    case "here":
      return upHere(sys, io, o, net);
    case "firewall": {
      const l = (await ask.line("This machine's private address, where other machines reach it (empty: this machine only): "))?.trim();
      return installFirewall(sys, io, { firewallImage: o.firewallImage, name: o.name, ...(l ? { listen: l } : {}) }, net);
    }
    case "openclaw": {
      const url = await askUrl();
      return url ? openclawInstall(sys, io, { firewall: url, name: o.name, vmAgent: o.vmAgent }, net) : 1;
    }
    default: {
      const url = await askUrl();
      return url ? connect(sys, io, { firewall: url, name: o.name, vmAgent: o.vmAgent }, net) : 1;
    }
  }
}

export function terminalIo(): Io {
  return { out: (l) => console.log(l), err: (l) => console.error(l), ask };
}

/** A line from the person at the terminal, not echoed; or the first line of stdin when it is not a terminal. */
function ask(prompt: string): Promise<string | null> {
  return new Promise((resolve) => {
    const tty = process.stdin.isTTY === true;
    const rl = createInterface({ input: process.stdin, output: tty ? process.stderr : undefined, terminal: tty });
    if (tty) {
      process.stderr.write(prompt);
      // Echo nothing of what is typed.
      (rl as unknown as { _writeToOutput: (s: string) => void })._writeToOutput = () => {};
    }
    let done = false;
    rl.once("line", (line) => {
      done = true;
      if (tty) process.stderr.write("\n");
      rl.close();
      resolve(line);
    });
    rl.once("close", () => {
      if (!done) resolve(null);
    });
    // Ctrl+C at the prompt stops connect, as anywhere else.
    rl.once("SIGINT", () => {
      if (tty) process.stderr.write("\n");
      rl.close();
      process.exit(130);
    });
  });
}
