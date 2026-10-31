/**
 * Where a residential exit can point (docs/features/residential-exit.md).
 *
 * The first entry is ControlClaw's own relay: the customer picks it and there is nothing to sign
 * up for, because ControlClaw holds the provider account and sells the bytes on at cost. The rest
 * are the customer's own account with a provider, which is the private option — those bytes are
 * billed by that provider to them, and ControlClaw never sees the traffic or the bill.
 *
 * The templates below are shapes read from public documentation and providers change them without
 * notice. Every field stays editable in the console, so a wrong preset is a typo a customer can
 * fix rather than a release.
 */

export type ExitScheme = "http" | "https" | "socks5";

export type ExitPreset = {
  id: string;
  name: string;
  /** One line under the name in the provider select. */
  blurb: string;
  scheme: ExitScheme;
  host: string;
  port: number;
  /**
   * `{username}`, `{session}`, `{country}` (uppercase) and `{country_lc}` (lowercase) are filled
   * by the firewall. A `[...]` segment is kept only when **every** placeholder inside it has a
   * value, and dropped whole otherwise — the only way one template can serve a sticky and a
   * rotating session, and a chosen country and no country, at once: without it, sticky-off
   * renders a dangling `-sessid-` and the provider refuses the credential.
   */
  usernameTemplate: string;
  /** `{password}` is filled by the firewall from its store; the same placeholders apply. */
  passwordTemplate: string;
  /** What the dialog says under the username field, in the provider's own terms. */
  usernameHelp?: string;
  /** Where that provider documents its proxy credentials. */
  docsUrl?: string;
  /**
   * True for the ControlClaw relay: there is no account to enter, the control plane mints the
   * credential itself and the console shows a balance instead of a credential form.
   */
  managed?: boolean;
};

/**
 * The relay's public name. Set `NEXT_PUBLIC_EXIT_RELAY_HOST` per environment; the fallback is the
 * production relay, so a preview deployment that forgets it still points somewhere real rather
 * than at localhost.
 */
export const EXIT_RELAY_HOST = process.env.NEXT_PUBLIC_EXIT_RELAY_HOST || "exit.controlclaw.com";
export const EXIT_RELAY_PORT = Number(process.env.NEXT_PUBLIC_EXIT_RELAY_PORT || 8443);

export const CONTROLCLAW_EXIT_PRESET_ID = "controlclaw";

export const EXIT_PRESETS: ReadonlyArray<ExitPreset> = [
  {
    id: CONTROLCLAW_EXIT_PRESET_ID,
    name: "ControlClaw residential (included)",
    blurb: "No account to set up. Your plan includes some data each month; buy more when you need it.",
    scheme: "https",
    host: EXIT_RELAY_HOST,
    port: EXIT_RELAY_PORT,
    // `[...]` is dropped by the firewall's renderer when the part inside has nothing to fill it,
    // so this one username carries every combination of country and sticky session. `controlclaw`
    // is a constant the relay ignores; it is there so the optional parts can all start with a
    // comma and none of them can leave a leading one.
    usernameTemplate: "controlclaw[,country-{country}][,session-{session}]",
    passwordTemplate: "{password}",
    managed: true,
  },
  {
    id: "apify",
    name: "Apify Proxy",
    blurb: "Your own Apify account.",
    scheme: "http",
    host: "proxy.apify.com",
    port: 8000,
    usernameTemplate: "groups-RESIDENTIAL[,country-{country}][,session-{session}]",
    passwordTemplate: "{password}",
    usernameHelp: "Apify identifies the account by the proxy password alone, so there is no user name to enter.",
    docsUrl: "https://docs.apify.com/platform/proxy/residential-proxy",
  },
  {
    id: "brightdata",
    name: "Bright Data",
    blurb: "Your own Bright Data zone.",
    scheme: "http",
    host: "brd.superproxy.io",
    port: 22225,
    usernameTemplate: "{username}[-country-{country_lc}][-session-{session}]",
    usernameHelp: "The zone user, e.g. brd-customer-hl_1a2b3c-zone-residential.",
    docsUrl: "https://docs.brightdata.com/proxy-networks/residential/quickstart",
    passwordTemplate: "{password}",
  },
  {
    id: "oxylabs",
    name: "Oxylabs",
    blurb: "Your own Oxylabs account.",
    scheme: "http",
    host: "pr.oxylabs.io",
    port: 7777,
    usernameTemplate: "customer-{username}[-cc-{country}][-sessid-{session}]",
    usernameHelp: "Your sub-user name, without the customer- prefix.",
    docsUrl: "https://developers.oxylabs.io/scraping-solutions/residential-proxies",
    passwordTemplate: "{password}",
  },
  {
    id: "decodo",
    name: "Decodo",
    blurb: "Your own Decodo account.",
    scheme: "http",
    host: "gate.decodo.com",
    port: 7000,
    usernameTemplate: "user-{username}[-country-{country_lc}][-session-{session}]",
    usernameHelp: "Your proxy user name, without the user- prefix.",
    docsUrl: "https://help.decodo.com/docs/residential-quick-start",
    passwordTemplate: "{password}",
  },
  {
    id: "iproyal",
    name: "IPRoyal",
    blurb: "Your own IPRoyal account. IPRoyal takes its options in the password.",
    scheme: "http",
    host: "geo.iproyal.com",
    port: 12321,
    usernameTemplate: "{username}",
    passwordTemplate: "{password}[_country-{country_lc}][_session-{session}]",
    usernameHelp: "Your royal residential user name.",
    docsUrl: "https://iproyal.com/residential-proxies/",
  },
  {
    id: "custom",
    name: "Another provider",
    blurb: "Enter the host, port and credential yourself.",
    scheme: "http",
    host: "",
    port: 8080,
    usernameTemplate: "{username}",
    passwordTemplate: "{password}",
    usernameHelp: "Anything that speaks HTTP CONNECT or SOCKS5 with a username and password.",
  },
];

export function findExitPreset(id: string): ExitPreset | undefined {
  return EXIT_PRESETS.find((p) => p.id === id);
}

/** Like `findExitPreset`, but always answers: an unknown id falls back to "Another provider". */
export function presetById(id: string): ExitPreset {
  return findExitPreset(id) ?? EXIT_PRESETS[EXIT_PRESETS.length - 1];
}

/**
 * Does this provider have a user name to type at all?
 *
 * Apify does not: its username field carries the group and the country, and the account is
 * identified by the password. A dialog that asks for one anyway makes a customer invent a value
 * that is then thrown away by the template — so the question is asked of the templates, not of a
 * list of provider ids, and a preset that stops using `{username}` stops asking for one.
 */
export function templatesUseUsername(usernameTemplate: string, passwordTemplate: string): boolean {
  return `${usernameTemplate} ${passwordTemplate}`.includes("{username}");
}

/**
 * Whether a country can be asked for at all — read off the templates, not a list of provider ids.
 *
 * It takes the templates rather than a preset because the live ones are the customer's: every
 * field on the Exit card is editable, so an exit set up before this existed, or one whose template
 * someone has edited, is judged by what it would actually render.
 */
export function templatesUseCountry(usernameTemplate: string, passwordTemplate: string): boolean {
  return /\{country(_lc)?\}/.test(`${usernameTemplate} ${passwordTemplate}`);
}

/** The hint the console shows in place of the account name: enough to recognise, not to reuse. */
export function accountHint(username: string): string {
  const clean = username.trim();
  if (clean.length <= 8) return clean ? `${clean.slice(0, 2)}…` : "";
  return `${clean.slice(0, 8)}…`;
}

/** The upstream block the firewall is handed when the customer picks the ControlClaw relay. */
export function controlclawExitUpstream() {
  const preset = EXIT_PRESETS[0];
  return {
    provider: preset.id,
    providerName: preset.name,
    scheme: preset.scheme,
    host: preset.host,
    port: preset.port,
    usernameTemplate: preset.usernameTemplate,
    passwordTemplate: preset.passwordTemplate,
  };
}
