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

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
