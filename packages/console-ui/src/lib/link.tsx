"use client";

import { createContext, useContext, type AnchorHTMLAttributes, type ComponentType, type ReactNode } from "react";

/**
 * The link the views render. The package knows no router: an app that has one (the console's
 * `next/link`, the panel's router link) passes it to `LinkProvider` once at the root, and every
 * `AppLink` uses it. Without a provider a link is a plain `<a>`, a full page load.
 */
export type LinkProps = AnchorHTMLAttributes<HTMLAnchorElement> & { href: string };
export type LinkComponent = ComponentType<LinkProps>;

const LinkContext = createContext<LinkComponent | null>(null);

export function LinkProvider({ component, children }: { component: LinkComponent; children: ReactNode }) {
  return <LinkContext.Provider value={component}>{children}</LinkContext.Provider>;
}

export function AppLink(props: LinkProps) {
  const Link = useContext(LinkContext);
  return Link ? <Link {...props} /> : <a {...props} />;
}
