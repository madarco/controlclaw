import { CONNECTOR_VERSION } from "./connector-version";

/**
 * Where an app's logo is served: `packages/console-ui/connector-icons/<service>.webp`, a 64x64 WebP
 * written by `apps/saas/scripts/gen-connector-icons.ts`. Both the console and the firewall's panel
 * serve them on their own origin under this path. The version is in the path so a new catalog gets
 * new URLs, since the files are cached for a year.
 */
export const CONNECTOR_ICON_PATH = "/connector-icons";

/** A service id as the catalog writes it, and the only form the servers answer for. */
const SERVICE = /^[a-z0-9][a-z0-9_-]{0,63}$/;

/** The logo's URL for a catalog app, or null when the id is not one a logo can have. */
export function connectorIconUrl(service: string): string | null {
  return SERVICE.test(service) ? `${CONNECTOR_ICON_PATH}/${CONNECTOR_VERSION}/${service}.webp` : null;
}
