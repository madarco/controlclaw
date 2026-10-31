import "./zod-config";
import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { App } from "./App";
import { applyTheme, savedTheme } from "./theme";
import { captureOauthParams } from "./oauth-params";
import "./styles.css";

applyTheme(savedTheme());
captureOauthParams();

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
