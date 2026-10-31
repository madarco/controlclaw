import { useCallback, type MouseEvent } from "react";
import { useRouter } from "@tanstack/react-router";
import { ApiProvider } from "@controlclaw/console-ui/lib/api";
import { LinkProvider, type LinkProps } from "@controlclaw/console-ui/lib/link";
import { RoutesProvider } from "@controlclaw/console-ui/lib/routes";
import { panelApi } from "./api/console-api";
import { PANEL_ROUTES } from "./routes";
import { Shell } from "./shell/Shell";

/** The shared views' links: an in-app path goes through the router, the rest load as usual. */
function RouterLink({ href, onClick, target, ...rest }: LinkProps) {
  const router = useRouter();
  const go = useCallback(
    (e: MouseEvent<HTMLAnchorElement>) => {
      onClick?.(e);
      if (e.defaultPrevented || e.button !== 0 || e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) return;
      if ((target && target !== "_self") || !href.startsWith("/") || href.startsWith("//")) return;
      e.preventDefault();
      router.history.push(href);
    },
    [href, onClick, target, router],
  );
  return <a href={href} target={target} onClick={go} {...rest} />;
}

export function Root() {
  return (
    <LinkProvider component={RouterLink}>
      <RoutesProvider routes={PANEL_ROUTES}>
        <ApiProvider api={panelApi}>
          <Shell />
        </ApiProvider>
      </RoutesProvider>
    </LinkProvider>
  );
}
