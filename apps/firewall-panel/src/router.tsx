import { createRootRoute, createRoute, createRouter } from "@tanstack/react-router";
import { HIDDEN, NAV } from "./pages";
import { Root } from "./Root";
import { ComingSoon } from "./pages/ComingSoon";

const root = createRootRoute({
  component: Root,
  notFoundComponent: () => <ComingSoon title="Not found" sub="There is no such page on this firewall." />,
});

const pages = [...NAV, ...HIDDEN].map((p) => createRoute({ getParentRoute: () => root, path: p.path, component: p.component }));

export const router = createRouter({ routeTree: root.addChildren(pages) });
