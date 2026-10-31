import type { User } from "./sys.js";

/** Groups whose members can have a daemon (dockerd, lxd, libvirt) send traffic for them. */
export const ESCAPE_GROUPS = ["docker", "lxd", "incus", "incus-admin", "libvirt", "podman"];

/** Why such a group defeats host mode, and the fix. Used by doctor and by host mode's check. */
export function escapeGroupMessage(user: User, groups: string[]): string {
  const removes = groups.map((g) => `gpasswd -d ${user.name} ${g}`).join("; ");
  return `${user.name} is in the ${groups.join(", ")} group: it can start a container or VM that the daemon sends out, past host mode's rules. Remove it (${removes}), or use docker mode`;
}
