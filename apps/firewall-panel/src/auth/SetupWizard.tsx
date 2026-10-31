import { useState } from "react";
import { Button } from "@controlclaw/console-ui/ui/button";
import { Input } from "@controlclaw/console-ui/ui/input";
import { Field } from "@controlclaw/console-ui/kit/console-ui";
import { errorText, fw } from "../api/client";
import { ModelKeyForm } from "../pages/ModelKeys";
import { PairAgent } from "../pages/PairAgent";
import { AuthFrame, FormError } from "./AuthFrame";
import { MIN_PASSWORD, passwordLength } from "./password";
import { useSession } from "./session";


/**
 * First run: the admin password, with the one-time token the firewall logs at start, then an AI
 * model key and the first agent, both optional.
 */
export function SetupWizard() {
  const session = useSession();
  const [step, setStep] = useState<"key" | "agent">("key");
  if (session.state === "setup") return <PasswordStep />;
  return step === "key" ? <ModelKeyStep next={() => setStep("agent")} /> : <AgentStep />;
}

function PasswordStep() {
  const session = useSession();
  const [token, setToken] = useState("");
  const [password, setPassword] = useState("");
  const [again, setAgain] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  const length = passwordLength(password);
  const tooShort = length > 0 && length < MIN_PASSWORD;
  const differ = again.length > 0 && again !== password;

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError("");
    try {
      await fw.post("/api/setup", { body: { token: token.trim(), password } });
      session.setUp();
    } catch (err) {
      setError(errorText(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <AuthFrame title="Set up this firewall" sub="Step 1 of 3. Choose the admin password for this panel.">
      <form onSubmit={submit} className="grid gap-4" data-testid="setup-form">
        <Field
          label="Setup token"
          htmlFor="token"
          hint={
            <>
              The firewall prints it in its log at start, on the line that begins with{" "}
              <code className="font-mono">[cc-local] no admin yet</code>. Read it with{" "}
              <code className="font-mono">journalctl -u controlclaw-mitm-agent</code>, or{" "}
              <code className="font-mono">docker compose logs firewall</code>. Only the newest one works.
            </>
          }
        >
          <Input id="token" autoComplete="off" spellCheck={false} autoFocus value={token} onChange={(e) => setToken(e.target.value)} className="font-mono" />
        </Field>
        <Field label="Password" htmlFor="new-password" hint={tooShort ? `At least ${MIN_PASSWORD} characters.` : `${MIN_PASSWORD} characters or more.`}>
          <Input id="new-password" type="password" autoComplete="new-password" value={password} onChange={(e) => setPassword(e.target.value)} aria-invalid={tooShort} />
        </Field>
        <Field label="Password again" htmlFor="again" hint={differ ? "The two passwords are not the same." : undefined}>
          <Input id="again" type="password" autoComplete="new-password" value={again} onChange={(e) => setAgain(e.target.value)} aria-invalid={differ} />
        </Field>
        <FormError>{error}</FormError>
        <Button type="submit" variant="brand" disabled={busy || !token.trim() || length < MIN_PASSWORD || again !== password}>
          {busy ? "Setting up…" : "Set password"}
        </Button>
      </form>
    </AuthFrame>
  );
}

function ModelKeyStep({ next }: { next: () => void }) {
  return (
    <AuthFrame
      title="Add an AI model key"
      sub="Step 2 of 3, optional. The firewall uses your own key for its AI review of what agents send. You can add one later in Settings."
    >
      <ModelKeyForm onDone={next} />
      <Button variant="ghost" className="mt-3 w-full" onClick={next} data-testid="setup-skip">
        Skip for now
      </Button>
    </AuthFrame>
  );
}

function AgentStep() {
  const session = useSession();
  return (
    <AuthFrame
      title="Connect your first agent"
      sub="Step 3 of 3, optional. Make a one-time code, then run the command on the machine that runs OpenClaw. You can do this later in Agents."
    >
      <PairAgent compact />
      <Button variant="ghost" className="mt-3 w-full" onClick={session.finishFirstRun} data-testid="setup-done">
        Go to the panel
      </Button>
    </AuthFrame>
  );
}
