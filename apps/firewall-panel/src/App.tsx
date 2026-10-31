import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { RouterProvider } from "@tanstack/react-router";
import { ThemeProvider, useTheme } from "./theme";
import { Button } from "@controlclaw/console-ui/ui/button";
import { Toaster } from "@controlclaw/console-ui/ui/sonner";
import { AuthFrame } from "./auth/AuthFrame";
import { LoginPage } from "./auth/LoginPage";
import { SessionProvider, useSession } from "./auth/session";
import { SetupWizard } from "./auth/SetupWizard";
import { router } from "./router";

const queryClient = new QueryClient({
  defaultOptions: { queries: { retry: 1, refetchOnWindowFocus: false } },
});

/** Setup, sign-in or the panel, as the firewall's session says. */
function Gate() {
  const session = useSession();
  switch (session.state) {
    case "loading":
      return (
        <div className="grid min-h-dvh place-items-center bg-bg-2 text-[13.5px] text-ink-2" role="status">
          Loading the firewall panel…
        </div>
      );
    case "unreachable":
      return (
        <AuthFrame title="The firewall did not answer" sub="Check that it is running, then try again.">
          <Button variant="brand" onClick={session.retry}>
            Try again
          </Button>
        </AuthFrame>
      );
    case "setup":
      return <SetupWizard />;
    case "signedOut":
    case "expired":
      return <LoginPage expired={session.state === "expired"} />;
    case "admin":
      return session.firstRun ? <SetupWizard /> : <RouterProvider router={router} />;
  }
}

/** The shared Toaster reads next-themes, which the panel does not use: it is told the theme. */
function ThemedToaster() {
  const { theme } = useTheme();
  return <Toaster theme={theme} />;
}

export function App() {
  return (
    <ThemeProvider>
      <QueryClientProvider client={queryClient}>
        <SessionProvider>
          <Gate />
        </SessionProvider>
        <ThemedToaster />
      </QueryClientProvider>
    </ThemeProvider>
  );
}
