/**
 * Where a residential exit should come out (apps/saas/docs/features/residential-exit.md).
 *
 * A country is a **two-letter ISO 3166-1 alpha-2 code**, stored uppercase, and that is the whole
 * contract. Nothing here decides whether a provider actually sells addresses in a country: the
 * codes below are the ones residential providers commonly offer, and a provider that refuses one
 * fails the connection closed with its own reason rather than being second-guessed from a table
 * that would go stale. Adding a country is a line in `COUNTRY_CODES`.
 *
 * Names come from `Intl.DisplayNames`, so this file carries codes and not a translation table.
 */

/** The shape, and the only thing any box validates. Uppercase is canonical. */
export const COUNTRY_CODE_RE = /^[A-Z]{2}$/;

/** `"de"` → `"DE"`; null for an empty value or anything that is not two letters. */
export function normalizeCountry(raw: string | null | undefined): string | null {
  const clean = (raw ?? "").trim().toUpperCase();
  return COUNTRY_CODE_RE.test(clean) ? clean : null;
}

/**
 * The codes the console offers. Residential pools are deepest in these, which is what makes them
 * worth offering; anything else is a template a customer can edit by hand on the Exit card.
 */
export const COUNTRY_CODES = [
  "AE", "AR", "AT", "AU", "BD", "BE", "BG", "BR", "CA", "CH", "CL", "CN", "CO", "CZ", "DE", "DK",
  "EG", "ES", "FI", "FR", "GB", "GR", "HK", "HR", "HU", "ID", "IE", "IL", "IN", "IQ", "IT", "JP",
  "KE", "KR", "KZ", "MA", "MX", "MY", "NG", "NL", "NO", "NZ", "PE", "PH", "PK", "PL", "PT", "RO",
  "RS", "SA", "SE", "SG", "SK", "TH", "TR", "TW", "UA", "US", "VN", "ZA",
] as const;

const DISPLAY = (() => {
  try {
    return new Intl.DisplayNames(["en"], { type: "region" });
  } catch {
    return null;
  }
})();

/** "DE" → "Germany". Falls back to the code itself where `Intl` has no name for it. */
export function countryName(code: string): string {
  const upper = code.toUpperCase();
  try {
    return DISPLAY?.of(upper) ?? upper;
  } catch {
    return upper;
  }
}

/** What a select renders: every offered code with its name, sorted by name. */
export function countryOptions(): Array<{ code: string; name: string }> {
  return COUNTRY_CODES.map((code) => ({ code, name: countryName(code) })).sort((a, b) => a.name.localeCompare(b.name));
}

/** The label for a country on a card or a rule row; "Any country" when none is set. */
export function countryLabel(code: string | null): string {
  return code ? `${countryName(code)} (${code})` : "Any country";
}
