import { useState } from "react";
import { Button } from "@controlclaw/console-ui/ui/button";
import { Input } from "@controlclaw/console-ui/ui/input";
import { Field } from "@controlclaw/console-ui/kit/console-ui";
import { errorText, fw } from "../api/client";
import { AuthFrame, FormError } from "./AuthFrame";
import { useSession } from "./session";

/** Sign in with the admin password; `expired` when the firewall ended the session. */
export function LoginPage({ expired }: { expired?: boolean }) {
  const session = useSession();
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError("");
    try {
      await fw.post("/api/login", { body: { password } });
      session.signedIn();
    } catch (err) {
      setError(errorText(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <AuthFrame
      title={expired ? "You were signed out" : "Sign in"}
      sub={expired ? "Your session ended. Sign in again to go on where you were." : "Sign in to this firewall with its admin password."}
    >
      <form onSubmit={submit} className="grid gap-4" data-testid="login-form">
        <Field label="Password" htmlFor="password">
          <Input id="password" type="password" autoComplete="current-password" autoFocus value={password} onChange={(e) => setPassword(e.target.value)} />
        </Field>
        <FormError>{error}</FormError>
        <Button type="submit" variant="brand" disabled={busy || !password}>
          {busy ? "Signing in…" : "Sign in"}
        </Button>
      </form>
    </AuthFrame>
  );
}
