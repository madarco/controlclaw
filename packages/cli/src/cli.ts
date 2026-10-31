import { createInterface } from "node:readline";
import { parseArgs } from "node:util";
import { connect, disconnect, doctor, type Io, status } from "./commands.js";
import { up } from "./local.js";
import { realSys, type Sys } from "./sys.js";

declare const __CC_CLI_VERSION__: string;
const VERSION = typeof __CC_CLI_VERSION__ === "string" ? __CC_CLI_VERSION__ : "0.0.0-dev";

export const USAGE = `controlclaw ${VERSION}

  Connect a machine that runs OpenClaw to a ControlClaw firewall.

  controlclaw doctor [--json]
      What this machine has, which modes it can do, and how much each protects.

  controlclaw connect --mode docker|host|proxy|remote --firewall <url> [--code - | --code-file <file>]
                      [--name <agent name>] [--proxy <host:port>] [--dns <ip>]
                      [--user <name>] [--vm-agent <path>]
      Pair with the firewall using a one-time code from it (mitm-agent pair-code), then install
      the vm-agent, the firewall's CA and the capture for the mode. --firewall is the firewall's
      pairing address, such as http://fw.example.com:8801. connect asks for the code; --code -
      reads it from stdin, --code-file from a file. --code <code> is refused: other users can read it.

  controlclaw connect --mode ... --firewall <url> --ca <file> [--firewall-key <pem>] ...
      The same without pairing: the firewall's CA and key by hand.
      --proxy defaults to what pairing says, else the firewall's host, port 8080; --dns likewise.

  controlclaw up --local --firewall-image <image> [--openclaw-image <image>] [--dir <folder>]
                 [--name <agent name>] [--vm-agent <path>]
      The firewall and OpenClaw as two containers on this machine, OpenClaw's only way out through
      the firewall, paired; prints the addresses of OpenClaw and of the firewall's panel.

  controlclaw disconnect [--force]
      Remove everything connect installed and put back what it changed. Steps that fail are kept
      for another try; --force gives them up.

  controlclaw status [--json]
      Whether the capture, the vm-agent and the firewall are up.

  Docker and host mode need root (sudo). Proxy mode works without it.
`;

export async function run(argv: string[], io: Io, sys: Sys = realSys()): Promise<number> {
  const [command, ...rest] = argv;
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
  switch (command) {
    case "doctor":
      return doctor(sys, io, { json: values.json === true, user: s("user"), vmAgent: s("vm-agent") });
    case "connect":
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
      });
    case "up":
      if (values.local !== true) {
        io.err("up --local is the only shape for now.");
        return 2;
      }
      return up(sys, io, {
        firewallImage: s("firewall-image"),
        openclawImage: s("openclaw-image"),
        dir: s("dir"),
        name: s("name"),
        vmAgent: s("vm-agent"),
      });
    case "disconnect":
      return disconnect(sys, io, { force: values.force === true });
    case "status":
      return status(sys, io, { json: values.json === true });
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
