import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { KeyRound, Trash2 } from "lucide-react";
import type { Schemas } from "@controlclaw/fw-api";
import { Button } from "@controlclaw/console-ui/ui/button";
import { Input } from "@controlclaw/console-ui/ui/input";
import { Checkbox } from "@controlclaw/console-ui/ui/checkbox";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@controlclaw/console-ui/ui/alert-dialog";
import { Badge, Card, EmptyState, Field, Select } from "@controlclaw/console-ui/kit/console-ui";
import { errorText, fw } from "../api/client";
import { FormError } from "../auth/AuthFrame";

type ModelKeys = Schemas["ModelKeys"];
type ModelKeyChange = Schemas["ModelKeyChange"];

const KEYS = ["llm-keys"] as const;

function useModelKeys() {
  return useQuery({ queryKey: KEYS, queryFn: () => fw.get("/api/llm/keys") });
}

/** A change the firewall refused is a 409 whose body is still a `ModelKeyChange`, with its reason. */
function refused(e: unknown): ModelKeyChange | null {
  const body = (e as { body?: Partial<ModelKeyChange> } | null)?.body;
  return body?.result && Array.isArray(body.keys) ? (body as ModelKeyChange) : null;
}

function refusal(e: unknown): string {
  return refused(e)?.result.message ?? errorText(e);
}

function useKeysAfter() {
  const qc = useQueryClient();
  return (change: ModelKeyChange) => qc.setQueryData<ModelKeys>(KEYS, (old) => (old ? { ...old, keys: change.keys } : old));
}

/** Add a model key: the provider, the key, an optional label. Shared by Settings and the setup wizard. */
export function ModelKeyForm({ onDone }: { onDone?: () => void }) {
  const keys = useModelKeys();
  const after = useKeysAfter();
  const providers = keys.data?.providers ?? [];
  const [provider, setProvider] = useState("");
  const [key, setKey] = useState("");
  const [label, setLabel] = useState("");
  const [replace, setReplace] = useState(false);
  const chosen = provider || providers[0]?.id || "";
  const has = keys.data?.keys.some((k) => k.provider === chosen) ?? false;

  const add = useMutation({
    mutationFn: () => fw.post("/api/llm/keys", { body: { provider: chosen, key: key.trim(), label: label.trim() || null, replace: has && replace } }),
    onSuccess: (change) => {
      after(change);
      if (change.result.ok) {
        setKey("");
        setLabel("");
        setReplace(false);
        onDone?.();
      }
    },
    onError: (e) => {
      const change = refused(e);
      if (change) after(change);
    },
  });
  const failed = add.data && !add.data.result.ok ? add.data.result.message : add.error ? refusal(add.error) : "";

  return (
    <form
      className="grid gap-4"
      data-testid="model-key-form"
      onSubmit={(e) => {
        e.preventDefault();
        add.mutate();
      }}
    >
      <Field label="Provider" htmlFor="provider">
        <Select id="provider" value={chosen} onChange={(e) => setProvider(e.target.value)} disabled={!providers.length}>
          {providers.map((p) => (
            <option key={p.id} value={p.id}>
              {p.name}
            </option>
          ))}
        </Select>
      </Field>
      <Field label="Key" htmlFor="model-key" hint="Kept only by the firewall. The panel shows its last four characters.">
        <Input id="model-key" type="password" autoComplete="off" spellCheck={false} value={key} onChange={(e) => setKey(e.target.value)} className="font-mono" />
      </Field>
      <Field label="Label (optional)" htmlFor="model-key-label">
        <Input id="model-key-label" value={label} onChange={(e) => setLabel(e.target.value)} />
      </Field>
      {has ? (
        <label className="flex items-center gap-2 text-[13px] text-ink-2">
          <Checkbox checked={replace} onCheckedChange={(v) => setReplace(v === true)} />
          Replace this provider&apos;s key
        </label>
      ) : null}
      <FormError>{keys.error ? errorText(keys.error) : failed}</FormError>
      <Button type="submit" variant="brand" disabled={add.isPending || !chosen || !key.trim() || (has && !replace)}>
        {add.isPending ? "Adding…" : "Add key"}
      </Button>
    </form>
  );
}

/** Settings → AI model keys: the keys the firewall holds, and adding or removing one. */
export function ModelKeysCard() {
  const keys = useModelKeys();
  const after = useKeysAfter();
  const [removing, setRemoving] = useState<Schemas["ModelKey"] | null>(null);
  const remove = useMutation({
    mutationFn: (provider: string) => fw.delete("/api/llm/keys/{provider}", { path: { provider }, body: {} }),
    onSuccess: (change) => {
      after(change);
      setRemoving(null);
    },
    onError: (e) => {
      const change = refused(e);
      if (change) after(change);
    },
  });
  const list = keys.data?.keys ?? [];

  return (
    <>
      <Card data-testid="model-keys">
        {keys.isPending ? (
          <div className="px-4 py-6 text-[13.5px] text-ink-2">Loading…</div>
        ) : list.length === 0 ? (
          <EmptyState icon={KeyRound} title="No model keys yet">
            Add one below. The AI review runs only with one of your own keys.
          </EmptyState>
        ) : (
          <ul className="divide-y divide-line">
            {list.map((k) => (
              <li key={k.id} className="flex items-center gap-3 px-4 py-3">
                <div className="min-w-0 flex-1">
                  <div className="flex flex-wrap items-center gap-2 text-[14px] font-medium text-ink">
                    {k.name}
                    {k.label ? <span className="font-normal text-ink-2">{k.label}</span> : null}
                    {k.state === "active" ? null : (
                      <Badge tone="block" dot>
                        Not taken
                      </Badge>
                    )}
                  </div>
                  <div className="font-mono text-[12.5px] text-ink-2">{k.hint}</div>
                  {k.lastError ? <div className="text-[12.5px] text-block">{k.lastError}</div> : null}
                </div>
                <Button variant="ghost" size="icon-sm" aria-label={`Remove the ${k.name} key`} onClick={() => {
                    remove.reset();
                    setRemoving(k);
                  }}
                >
                  <Trash2 />
                </Button>
              </li>
            ))}
          </ul>
        )}
      </Card>
      <Card className="mt-3 p-4 sm:p-5">
        <ModelKeyForm />
      </Card>
      <AlertDialog open={removing !== null} onOpenChange={(o) => (o ? null : setRemoving(null))}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Remove the {removing?.name} key?</AlertDialogTitle>
            <AlertDialogDescription>The firewall forgets it. An AI review that uses it stops until you add another key.</AlertDialogDescription>
          </AlertDialogHeader>
          <FormError>{remove.error ? refusal(remove.error) : ""}</FormError>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction
              onClick={(e) => {
                e.preventDefault();
                if (removing) remove.mutate(removing.provider);
              }}
              disabled={remove.isPending}
            >
              Remove
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </>
  );
}
