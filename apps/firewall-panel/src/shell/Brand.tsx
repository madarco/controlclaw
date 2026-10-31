import { brandMark } from "@controlclaw/cc-shell";

/** The ControlClaw mark and name, as on the firewall's other pages. */
export function Brand({ size = 26 }: { size?: number }) {
  return (
    <span className="flex items-center gap-[9px]">
      {/* A fixed SVG from cc-shell, the same the firewall's own pages draw. */}
      <span className="flex" dangerouslySetInnerHTML={{ __html: brandMark(size) }} />
      <span className="text-[15px] font-semibold tracking-[-0.01em] text-ink">ControlClaw</span>
    </span>
  );
}
