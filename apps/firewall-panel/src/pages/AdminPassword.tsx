import { useState } from "react";
import { useMutation } from "@tanstack/react-query";
import { toast } from "sonner";
import { Button } from "@controlclaw/console-ui/ui/button";
import { Input } from "@controlclaw/console-ui/ui/input";
import { Card, Field } from "@controlclaw/console-ui/kit/console-ui";
import { errorText, fw } from "../api/client";
import { FormError } from "../auth/AuthFrame";
import { MIN_PASSWORD, passwordLength } from "../auth/password";

/** Change the admin password. The firewall signs out every other browser; this one stays in. */
export function AdminPasswordCard() {
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [again, setAgain] = useState("");
  const length = passwordLength(next);
  const tooShort = length > 0 && length < MIN_PASSWORD;
  const differ = again.length > 0 && again !== next;
  const change = useMutation({
    mutationFn: () => fw.post("/api/admin/password", { body: { current, new: next } }),
    onSuccess: (r) => {
      setCurrent("");
      setNext("");
      setAgain("");
      toast.success(r.signedOut ? "Password changed. Other browsers signed in to this firewall are signed out." : "Password changed.");
    },
  });
  return (
    <Card className="px-4 py-4 sm:px-5">
      <form
        className="grid max-w-[26rem] gap-4"
        data-testid="admin-password"
        onSubmit={(e) => {
          e.preventDefault();
          change.mutate();
        }}
      >
        <Field label="Current password" htmlFor="current-password">
          <Input id="current-password" type="password" autoComplete="current-password" value={current} onChange={(e) => setCurrent(e.target.value)} />
        </Field>
        <Field label="New password" htmlFor="admin-new-password" hint={tooShort ? `At least ${MIN_PASSWORD} characters.` : `${MIN_PASSWORD} characters or more.`}>
          <Input id="admin-new-password" type="password" autoComplete="new-password" value={next} onChange={(e) => setNext(e.target.value)} aria-invalid={tooShort} />
        </Field>
        <Field label="New password again" htmlFor="admin-again" hint={differ ? "The two passwords are not the same." : undefined}>
          <Input id="admin-again" type="password" autoComplete="new-password" value={again} onChange={(e) => setAgain(e.target.value)} aria-invalid={differ} />
        </Field>
        <FormError>{change.error ? errorText(change.error) : ""}</FormError>
        <div className="flex flex-wrap items-center gap-3">
          <Button type="submit" variant="brand" disabled={change.isPending || !current || length < MIN_PASSWORD || again !== next}>
            {change.isPending ? "Changing…" : "Change password"}
          </Button>
        </div>
        <p className="text-[12.5px] text-ink-2">
          Forgot it? On the firewall&apos;s machine, run <code className="font-mono">mitm-agent reset-admin</code>: it prints a new setup token
          and signs everyone out.
        </p>
      </form>
    </Card>
  );
}
