"use client";

import { Select } from "../../kit/console-ui";
import type { EveryOtherSite } from "./useEgressRules";

/** "Every other site": Allow or Block, where a person can choose it (the firewall's own panel). */
export function EveryOtherSiteSelect({
  value,
  disabled,
  onChange,
}: {
  value: EveryOtherSite | "unknown";
  disabled?: boolean;
  onChange: (effect: EveryOtherSite) => void;
}) {
  return (
    <Select
      className="h-8 w-auto min-w-[6.5rem] text-[13px]"
      aria-label="Every other site"
      value={value === "unknown" ? "" : value}
      disabled={disabled || value === "unknown"}
      onChange={(e) => onChange(e.target.value as EveryOtherSite)}
      data-testid="every-other-site"
    >
      {value === "unknown" ? <option value="">…</option> : null}
      <option value="allow">Allow</option>
      <option value="block">Block</option>
    </Select>
  );
}
