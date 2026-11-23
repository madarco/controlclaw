import "./zod-config";
import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { App } from "./App";
import { applyTheme, savedTheme } from "./theme";
import { captureOauthParams } from "./oauth-params";
import { captureSetupToken } from "./setup-token";
import "./styles.css";

applyTheme(savedTheme());
captureOauthParams();
captureSetupToken();
window.addEventListener("hashchange", captureSetupToken);

async function start() {
  // `pnpm dev` only: a build replaces `import.meta.env.DEV` with false and drops the fake.
  if (import.meta.env.DEV && import.meta.env.VITE_FAKE_BRAIN === "1") {
    const [{ fakeBrain }, { setBrainSource }] = await Promise.all([import("./api/fake-brain"), import("./api/brain")]);
    setBrainSource(fakeBrain());
  }
  createRoot(document.getElementById("root")!).render(
    <StrictMode>
      <App />
    </StrictMode>,
  );
}

void start();
