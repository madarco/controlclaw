import { Ban, Check, UserCheck } from "lucide-react";
import type { ComponentType } from "react";
import type { RuleEffect } from "../../lib/rule-types";

export type EffectDisplay = {
  label: string;
  icon: ComponentType<{ className?: string }>;
  chipTone: string;
  borderTone: string;
};

export const EFFECT_DISPLAY: Record<RuleEffect, EffectDisplay> = {
  allow: {
    label: "Allow",
    icon: Check,
    chipTone: "bg-allow-soft text-allow-fg hover:bg-allow-soft/80",
    borderTone: "bg-allow-soft text-allow-fg border-allow-border",
  },
  ask: {
    label: "Ask",
    icon: UserCheck,
    chipTone: "bg-ask-soft text-ask-fg hover:bg-ask-soft/80",
    borderTone: "bg-ask-soft text-ask-fg border-ask-border",
  },
  block: {
    label: "Block",
    icon: Ban,
    chipTone: "bg-block-soft text-block-fg hover:bg-block-soft/80",
    borderTone: "bg-block-soft text-block-fg border-block-border",
  },
};
