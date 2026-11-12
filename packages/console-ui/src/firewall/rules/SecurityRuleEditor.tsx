"use client";

import { useState } from "react";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { Loader2, Trash2 } from "lucide-react";
import { toast } from "sonner";
import { Button } from "../../ui/button";
import { Input } from "../../ui/input";
import { Textarea } from "../../ui/textarea";
import { Checkbox } from "../../ui/checkbox";
import {
  Dialog,
  DialogContent,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogDescription,
} from "../../ui/dialog";
import {
  Form,
  FormControl,
  FormField,
  FormItem,
  FormLabel,
  FormMessage,
} from "../../ui/form";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "../../ui/alert-dialog";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "../../ui/select";
import { useApi } from "../../lib/api";
import { cn } from "../../lib/utils";
import type { PermissionKind } from "../../lib/permission-kinds";
import {
  createSecurityRuleInputSchema,
  type RuleEffect,
  type SecurityRuleListItem,
} from "../../lib/security-schema";
import { EFFECT_DISPLAY } from "./effect-display";
import { itemToAutoRule, newAutoRuleId, type AutoApproveChange } from "../../lib/auto-approve-schema";

const EFFECT_ORDER: RuleEffect[] = ["allow", "ask", "block"];

type FormValues = {
  name: string;
  description: string;
  condDisplay: string;
  enabled: boolean;
  priority: number;
  kinds: PermissionKind[];
  titleLike: string;
  titleMatch: "contains" | "exact";
  vmId: string;
  effect: RuleEffect;
};

const ANY_VM = "__any__";

const KIND_OPTIONS: Array<{ value: PermissionKind; label: string }> = [
  { value: "payment", label: "Payment" },
  { value: "delete", label: "Delete" },
  { value: "access", label: "Outbound call" },
  { value: "app_call", label: "App or MCP tool call" },
  { value: "exec", label: "Shell command" },
  { value: "plugin", label: "Plugin action" },
  { value: "system", label: "System agent" },
  { value: "other", label: "Other" },
];

interface SecurityRuleEditorProps {
  mode: "create" | "edit";
  initial: SecurityRuleListItem | null;
  vmOptions: Array<{ id: string; name: string }>;
  onClose: () => void;
  onSaved: (rule: SecurityRuleListItem) => void;
  onDeleted: (id: string) => void;
  /** The demo page: saving and deleting only close the dialog. */
  demo?: boolean;
  /**
   * The firewall keeps the rules: saving and deleting send it a change (which may wait for its code)
   * and close the dialog. `priority` is then the rule's place in the firewall's list.
   */
  onPropose?: (change: AutoApproveChange) => void;
  /** With `onPropose`: how many rules the firewall holds. */
  ruleCount?: number;
}

export function SecurityRuleEditor({
  mode,
  initial,
  vmOptions,
  onClose,
  onSaved,
  onDeleted,
  demo,
  onPropose,
  ruleCount = 0,
}: SecurityRuleEditorProps) {
  const onFirewall = !!onPropose;
  const api = useApi();
  const [saving, setSaving] = useState(false);
  const [pendingDelete, setPendingDelete] = useState(false);
  const [deleting, setDeleting] = useState(false);

  const form = useForm<FormValues>({
    resolver: zodResolver(createSecurityRuleInputSchema) as never,
    defaultValues: {
      name: initial?.name ?? "",
      description: initial?.description ?? "",
      condDisplay: initial?.condDisplay ?? "",
      enabled: initial?.enabled ?? true,
      // On the firewall, the place in its list, from 1; a new rule goes last.
      priority: onPropose ? (initial ? initial.priority + 1 : ruleCount + 1) : (initial?.priority ?? 100),
      kinds: (initial?.kinds ?? []) as PermissionKind[],
      titleLike: initial?.titleLike ?? "",
      titleMatch: initial?.titleMatch ?? "contains",
      vmId: initial?.vmId ?? ANY_VM,
      effect: initial?.effect ?? "ask",
    },
  });

  const propose = (values: FormValues) => {
    const rule = itemToAutoRule(initial?.id ?? newAutoRuleId(), {
      name: values.name,
      description: values.description,
      kinds: values.kinds,
      titleLike: values.titleLike,
      titleMatch: values.titleMatch,
      vmId: values.vmId === ANY_VM ? null : values.vmId,
      effect: values.effect,
      enabled: values.enabled,
    });
    const place = Math.max(0, Math.min(values.priority - 1, initial ? ruleCount - 1 : ruleCount));
    if (!initial) return onPropose!({ op: "put", rule, at: place });
    const same = JSON.stringify(itemToAutoRule(initial.id, { ...initial, effect: initial.effect })) === JSON.stringify(rule);
    if (place !== initial.priority && !same) {
      form.setError("priority", { message: "Change the position on its own, then save the rest." });
      return;
    }
    onPropose!(place !== initial.priority ? { op: "move", id: initial.id, to: place } : { op: "put", rule });
  };

  const onSubmit = async (values: FormValues) => {
    if (demo) return onClose();
    if (onFirewall) {
      propose(values);
      return;
    }
    setSaving(true);
    try {
      const condDisplay = values.condDisplay.trim();
      const titleLike = values.titleLike.trim();
      const payload = {
        name: values.name,
        description: values.description,
        condDisplay: condDisplay === "" ? null : condDisplay,
        enabled: values.enabled,
        priority: values.priority,
        kinds: values.kinds,
        titleLike: titleLike === "" ? null : titleLike,
        titleMatch: values.titleMatch,
        vmId: values.vmId === ANY_VM ? null : values.vmId,
        effect: values.effect,
      };
      const security = api.security;
      if (!security) throw new Error("No auto approve rules on this control plane");
      const saved =
        mode === "create"
          ? await security.createSecurityRule(payload)
          : await security.updateSecurityRule({ id: initial!.id, ...payload });
      toast.success(mode === "create" ? `Rule "${saved.name}" created` : `Rule "${saved.name}" updated`);
      onSaved(saved);
    } catch (err) {
      console.error("save rule failed", err);
      toast.error("Couldn’t save the rule. Try again.");
    } finally {
      setSaving(false);
    }
  };

  const onConfirmDelete = async () => {
    if (demo) return onClose();
    if (!initial) return;
    if (onFirewall) {
      setPendingDelete(false);
      onPropose!({ op: "delete", id: initial.id });
      return;
    }
    setDeleting(true);
    try {
      if (!api.security) throw new Error("No auto approve rules on this control plane");
      await api.security.deleteSecurityRule({ id: initial.id });
      toast.success(`Deleted "${initial.name}"`);
      onDeleted(initial.id);
    } catch (err) {
      console.error("delete rule failed", err);
      toast.error("Couldn’t delete the rule. Try again.");
    } finally {
      setDeleting(false);
      setPendingDelete(false);
    }
  };

  return (
    <>
      <Dialog open onOpenChange={(open) => !open && !saving && onClose()}>
        <DialogContent className="sm:max-w-[560px]">
          <DialogHeader>
            <DialogTitle>{mode === "create" ? "New Auto approve rule" : "Edit Auto approve rule"}</DialogTitle>
            <DialogDescription>
              {onFirewall
                ? "Answers your agents’ permission requests without you. Your firewall reads the rules in order, and the first match decides: allow, ask, or block. A change that lets more through waits for the code your firewall sends."
                : "Answers your agents’ permission requests without you. Rules run in priority order, and the first match decides: allow, ask, or block. Changes apply at once."}
            </DialogDescription>
          </DialogHeader>

          <Form {...form}>
            <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-4" id="security-rule-form">
              <FormField
                control={form.control}
                name="name"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>Name</FormLabel>
                    <FormControl>
                      <Input placeholder="Large payments" {...field} />
                    </FormControl>
                    <FormMessage />
                  </FormItem>
                )}
              />

              <FormField
                control={form.control}
                name="description"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>Description</FormLabel>
                    <FormControl>
                      <Textarea
                        placeholder="Human approval required before sending funds."
                        rows={2}
                        {...field}
                      />
                    </FormControl>
                    <FormMessage />
                  </FormItem>
                )}
              />

              <FormField
                control={form.control}
                name="effect"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>Action</FormLabel>
                    <div className="flex gap-2">
                      {EFFECT_ORDER.map((value) => {
                        const display = EFFECT_DISPLAY[value];
                        const Icon = display.icon;
                        const active = field.value === value;
                        return (
                          <button
                            key={value}
                            type="button"
                            onClick={() => field.onChange(value)}
                            className={cn(
                              "inline-flex h-9 flex-1 items-center justify-center gap-1.5 rounded-[8px] border px-3 text-[13px] font-semibold transition-colors",
                              active ? display.borderTone : "border-line bg-surface text-ink-2 hover:bg-bg-2",
                            )}
                          >
                            <Icon className="h-3.5 w-3.5" />
                            {display.label}
                          </button>
                        );
                      })}
                    </div>
                    <FormMessage />
                  </FormItem>
                )}
              />

              <FormField
                control={form.control}
                name="kinds"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>Matches kinds</FormLabel>
                    <div className="flex flex-wrap gap-x-4 gap-y-2">
                      {KIND_OPTIONS.map((k) => {
                        const checked = field.value.includes(k.value);
                        return (
                          <label key={k.value} className="flex cursor-pointer items-center gap-2 text-[13px]">
                            <Checkbox
                              checked={checked}
                              onCheckedChange={(state) => {
                                const v = state === true;
                                if (v && !checked) field.onChange([...field.value, k.value]);
                                else if (!v && checked) field.onChange(field.value.filter((x) => x !== k.value));
                              }}
                            />
                            {k.label}
                          </label>
                        );
                      })}
                    </div>
                    <p className="text-[12px] text-ink-2">Leave empty to match any kind.</p>
                    <FormMessage />
                  </FormItem>
                )}
              />

              <div className="grid grid-cols-[1fr_160px] gap-4">
                <FormField
                  control={form.control}
                  name="titleLike"
                  render={({ field }) => (
                    <FormItem>
                      <FormLabel>Title (optional)</FormLabel>
                      <FormControl>
                        <Input placeholder="e.g. production" {...field} />
                      </FormControl>
                      <FormMessage />
                    </FormItem>
                  )}
                />
                <FormField
                  control={form.control}
                  name="titleMatch"
                  render={({ field }) => (
                    <FormItem>
                      <FormLabel>Match</FormLabel>
                      <Select value={field.value} onValueChange={field.onChange}>
                        <FormControl>
                          <SelectTrigger>
                            <SelectValue />
                          </SelectTrigger>
                        </FormControl>
                        <SelectContent>
                          <SelectItem value="contains">contains</SelectItem>
                          <SelectItem value="exact">is exactly</SelectItem>
                        </SelectContent>
                      </Select>
                      <FormMessage />
                    </FormItem>
                  )}
                />
              </div>

              <div className="grid grid-cols-2 gap-4">
                <FormField
                  control={form.control}
                  name="vmId"
                  render={({ field }) => (
                    <FormItem>
                      <FormLabel>Agent</FormLabel>
                      <Select value={field.value} onValueChange={field.onChange}>
                        <FormControl>
                          <SelectTrigger>
                            <SelectValue />
                          </SelectTrigger>
                        </FormControl>
                        <SelectContent>
                          <SelectItem value={ANY_VM}>Any agent</SelectItem>
                          {vmOptions.map((v) => (
                            <SelectItem key={v.id} value={v.id}>
                              {v.name}
                            </SelectItem>
                          ))}
                        </SelectContent>
                      </Select>
                      <FormMessage />
                    </FormItem>
                  )}
                />

                <FormField
                  control={form.control}
                  name="priority"
                  render={({ field }) => (
                    <FormItem>
                      <FormLabel>{onFirewall ? "Position" : "Priority"}</FormLabel>
                      <FormControl>
                        <Input
                          type="number"
                          min={onFirewall ? 1 : 0}
                          max={onFirewall ? Math.max(1, initial ? ruleCount : ruleCount + 1) : undefined}
                          step={1}
                          value={field.value}
                          onChange={(e) => field.onChange(Number.parseInt(e.target.value || "0", 10))}
                        />
                      </FormControl>
                      <FormMessage />
                    </FormItem>
                  )}
                />
              </div>

              {/* The firewall builds the condition from the fields; it keeps no label of its own. */}
              {!onFirewall && (
              <FormField
                control={form.control}
                name="condDisplay"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>Condition label (optional)</FormLabel>
                    <FormControl>
                      <Input placeholder="amount > $1,000" {...field} />
                    </FormControl>
                    <p className="text-[12px] text-ink-2">
                      Shown under Matches in the rules list. Leave it empty to build it from the fields above.
                    </p>
                    <FormMessage />
                  </FormItem>
                )}
              />
              )}
            </form>
          </Form>

          <DialogFooter className="flex items-center sm:justify-between">
            {mode === "edit" && initial ? (
              <Button
                type="button"
                variant="ghost"
                className="text-block-fg hover:text-block-fg"
                onClick={() => setPendingDelete(true)}
                disabled={saving || deleting}
              >
                <Trash2 className="h-4 w-4" />
                Delete
              </Button>
            ) : (
              <span />
            )}
            <div className="flex gap-2">
              <Button type="button" variant="outline" onClick={onClose} disabled={saving}>
                Cancel
              </Button>
              <Button type="submit" form="security-rule-form" variant="brand" disabled={saving}>
                {saving && <Loader2 className="h-4 w-4 animate-spin" />}
                {mode === "create" ? "Create rule" : "Save changes"}
              </Button>
            </div>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {pendingDelete && initial && (
        <AlertDialog open onOpenChange={(open) => !open && !deleting && setPendingDelete(false)}>
          <AlertDialogContent>
            <AlertDialogHeader>
              <AlertDialogTitle>Delete “{initial.name}”?</AlertDialogTitle>
              <AlertDialogDescription>
                This rule stops checking incoming permission requests. You can create it again later.
              </AlertDialogDescription>
            </AlertDialogHeader>
            <AlertDialogFooter>
              <AlertDialogCancel disabled={deleting}>Cancel</AlertDialogCancel>
              <AlertDialogAction
                onClick={(e) => {
                  e.preventDefault();
                  void onConfirmDelete();
                }}
                disabled={deleting}
              >
                {deleting && <Loader2 className="h-4 w-4 animate-spin" />}
                Delete rule
              </AlertDialogAction>
            </AlertDialogFooter>
          </AlertDialogContent>
        </AlertDialog>
      )}
    </>
  );
}
