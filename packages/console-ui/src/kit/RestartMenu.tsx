"use client";

import { ChevronDown, Loader2, Power, RotateCw, PowerOff } from "lucide-react";
import { Button } from "../ui/button";
import { ButtonGroup } from "../ui/button-group";
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger } from "../ui/dropdown-menu";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "../ui/alert-dialog";
import { cn } from "../lib/utils";

/**
 * Restart with a dropdown arrow beside it, holding one item: Hard reboot. Used on an agent's page,
 * the Firewall page and the Brain page (docs/features/agent-settings.md, firewall.md).
 *
 * Restart restarts the service on the box. Hard reboot reboots the server itself at Hetzner, for
 * when the box is stuck and Restart cannot reach it — so the arrow stays usable when Restart is
 * disabled because the box is not answering.
 */
export function RestartMenu({
  label = "Restart",
  onRestart,
  restartDisabled,
  spinning,
  busy,
  variant = "outline",
  onHardReboot,
  hardRebootDisabled,
  onPowerOff,
  testId,
}: {
  /** The main button's text. The firewall's recovery path turns it into "Power on" or "Rebuild". */
  label?: string;
  onRestart: () => void;
  restartDisabled?: boolean;
  /** Spin the restart icon (a restart or recovery in flight). */
  spinning?: boolean;
  /** Show a spinner in place of the icon. */
  busy?: boolean;
  variant?: "outline" | "default";
  /** Left out where the control plane cannot reboot the server: then Restart has no menu. */
  onHardReboot?: () => void;
  /** Hard reboot needs a server at Hetzner and the right role; without both the arrow is greyed. */
  hardRebootDisabled?: boolean;
  /** Power the server off, where the page offers it (an agent's). Left out, the item is not there. `<testId>-power-off`. */
  onPowerOff?: () => void;
  /** `<testId>` on Restart, `<testId>-more` on the arrow, `<testId>-hard-reboot` on the item. */
  testId: string;
}) {
  const restart = (
    <Button size="sm" variant={variant} disabled={restartDisabled} onClick={onRestart} data-testid={testId}>
      {busy ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <RotateCw className={cn("h-3.5 w-3.5", spinning && "animate-spin")} />}
      {label}
    </Button>
  );
  if (!onHardReboot) return restart;
  return (
    <ButtonGroup>
      {restart}
      <DropdownMenu>
        <DropdownMenuTrigger asChild>
          <Button
            size="sm"
            variant={variant}
            className="!px-1.5"
            disabled={hardRebootDisabled}
            aria-label="More restart options"
            data-testid={`${testId}-more`}
          >
            <ChevronDown className="h-3.5 w-3.5" />
          </Button>
        </DropdownMenuTrigger>
        <DropdownMenuContent align="end" className="w-[240px]">
          <DropdownMenuItem
            onSelect={onHardReboot}
            className="cursor-pointer items-start gap-2.5"
            data-testid={`${testId}-hard-reboot`}
          >
            <Power className="mt-0.5 h-4 w-4 text-ink-2" />
            <span className="min-w-0">
              <span className="block">Hard reboot</span>
              <span className="block text-[11.5px] text-ink-2">Reboot the whole server, for when Restart doesn’t help</span>
            </span>
          </DropdownMenuItem>
          {onPowerOff ? (
            <DropdownMenuItem onSelect={onPowerOff} className="cursor-pointer items-start gap-2.5" data-testid={`${testId}-power-off`}>
              <PowerOff className="mt-0.5 h-4 w-4 text-ink-2" />
              <span className="min-w-0">
                <span className="block">Power off</span>
                <span className="block text-[11.5px] text-ink-2">Turn the server off until you turn it on again</span>
              </span>
            </DropdownMenuItem>
          ) : null}
        </DropdownMenuContent>
      </DropdownMenu>
    </ButtonGroup>
  );
}

/** The confirm step for Hard reboot, in the console's standard dialog. */
export function HardRebootDialog({
  open,
  onOpenChange,
  name,
  onConfirm,
  effect = "Chats stop",
  testId = "hard-reboot-confirm",
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  /** What is rebooted: the agent's name, "the firewall", "the brain". */
  name: string;
  onConfirm: () => void;
  /** What stops while it is down. An agent's chats by default; the firewall and brain say their own. */
  effect?: string;
  testId?: string;
}) {
  return (
    <AlertDialog open={open} onOpenChange={onOpenChange}>
      <AlertDialogContent>
        <AlertDialogHeader>
          <AlertDialogTitle>Hard reboot {name}?</AlertDialogTitle>
          <AlertDialogDescription>
            This restarts the whole server, like pressing its power button. {effect} for about a minute or two; nothing is deleted.
          </AlertDialogDescription>
        </AlertDialogHeader>
        <AlertDialogFooter>
          <AlertDialogCancel>Cancel</AlertDialogCancel>
          <AlertDialogAction
            onClick={() => {
              onOpenChange(false);
              onConfirm();
            }}
            data-testid={testId}
          >
            Hard reboot
          </AlertDialogAction>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  );
}

/** The toast after a hard reboot was accepted. */
export const HARD_REBOOT_TOAST = "Hard reboot sent. The server takes a minute or two to come back.";
