import { readFileSync } from "node:fs";
import { FakeSys } from "./sys.js";

/** Test fixtures: a recorded output from testdata/. */
export function fixture(name: string): string {
  return readFileSync(new URL(`./testdata/${name}`, import.meta.url), "utf8");
}

export const CA = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n";
export const KEY = "-----BEGIN PUBLIC KEY-----\nMCow\n-----END PUBLIC KEY-----\n";

/**
 * An Ubuntu 24.04 box as `connect` sees it: root, systemd, nft, apt, resolved, a vm-agent binary,
 * and OpenClaw from the official installer running as `claw` (or in Docker).
 */
export function fakeMachine(kind: "systemd-user" | "docker"): FakeSys {
  const sys = new FakeSys();
  sys.files.set("/etc/os-release", 'PRETTY_NAME="Ubuntu 24.04.3 LTS"\n');
  sys.files.set("/etc/passwd", "root:x:0:0:root:/root:/bin/bash\nclaw:x:1001:1001::/home/claw:/bin/bash\nsystemd-resolve:x:991:991::/:/usr/sbin/nologin\n");
  sys.files.set("/etc/resolv.conf", "nameserver 127.0.0.53\n");
  sys.files.set("/run/systemd/system/.keep", "");
  sys.files.set("/tmp/ca.pem", CA);
  sys.files.set("/tmp/fw.pem", KEY);
  sys.files.set("/opt/vm-agent", "ELF");
  // claw's home is claw's: root writes there as claw (Recorder.file).
  sys.files.set("/home/claw/", "");
  sys.owners.set("/home/claw", 1001);
  // Later answers win: the catch-all first.
  sys.on("sh -c command -v", { code: 1 });
  const has = (n: string, p: string) => sys.on(`sh -c command -v "$1" sh ${n}`, { stdout: `${p}\n` });
  has("nft", "/usr/sbin/nft");
  has("apt-get", "/usr/bin/apt-get");
  sys.on("systemctl is-active", { stdout: "active\n" });
  sys.on("systemctl show -p ActiveState,NRestarts", { stdout: "NRestarts=0\nActiveState=active\n" });
  sys.on("curl -sS -o /dev/null", { stdout: "200" });
  sys.on("docker version", { stdout: "29.1.3\n" });
  sys.on("docker compose version", { stdout: "2.40.3\n" });
  sys.on("id -nG claw", { stdout: "claw\n" });
  sys.on("proxy validate --json", { stdout: fixture("proxy-validate.json") });
  if (kind === "systemd-user") {
    sys.on("ps -eo", { stdout: "    0     1 /sbin/init\n 1001  4242 openclaw-gateway\n" });
    sys.files.set("/proc/4242/cgroup", "0::/user.slice/user-1001.slice/user@1001.service/app.slice/openclaw-gateway.service\n");
    sys.on("runuser -u claw -- env HOME=/home/claw XDG_RUNTIME_DIR=/run/user/1001 /opt/vm-agent discover", { stdout: fixture("discover-systemd-user.json") });
  } else {
    sys.on("ps -eo", { stdout: "    0     1 /sbin/init\n 1000  777 node dist/index.js gateway --bind lan\n" });
    sys.files.set("/proc/777/cgroup", "0::/system.slice/docker-abc.scope\n");
    sys.on("/opt/vm-agent discover", { stdout: fixture("discover-docker.json") });
    sys.on("docker inspect -- openclaw-openclaw-gateway-1", { stdout: fixture("inspect-compose.json") });
    sys.on("docker network inspect", { stdout: "[]" });
    sys.on("docker exec openclaw-openclaw-gateway-1 cat", { stdout: "-----BEGIN CERTIFICATE-----\nIMAGE\n-----END CERTIFICATE-----\n" });
  }
  return sys;
}
