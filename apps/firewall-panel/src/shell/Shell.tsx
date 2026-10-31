import { useEffect, useRef, useState, type ComponentType, type ReactNode } from "react";
import { Link, Outlet, useRouterState } from "@tanstack/react-router";
import { LogOut, Moon, Sun } from "lucide-react";
import { Button } from "@controlclaw/console-ui/ui/button";
import { cn } from "@controlclaw/console-ui/lib/utils";
import { useSession } from "../auth/session";
import { NAV } from "../pages";
import { Brand } from "./Brand";
import { useTheme } from "../theme";
import { StopBanner, StopButton } from "../pages/Stop";

function NavLink({ to, icon: Icon, children }: { to: string; icon: ComponentType<{ className?: string }>; children: ReactNode }) {
  const path = useRouterState({ select: (s) => s.location.pathname });
  const active = to === "/" ? path === "/" : path === to || path.startsWith(`${to}/`);
  const ref = useRef<HTMLAnchorElement>(null);
  // On a phone the nav is one scrolling row: keep the open page in sight.
  useEffect(() => {
    if (active) ref.current?.scrollIntoView({ block: "nearest", inline: "nearest" });
  }, [active]);
  return (
    <Link
      ref={ref}
      to={to}
      aria-current={active ? "page" : undefined}
      className={cn(
        "flex shrink-0 items-center gap-[11px] rounded-lg px-[10px] py-2 text-[13.5px]",
        active ? "bg-surface font-semibold text-ink shadow-sm" : "text-ink-2 hover:bg-bg",
      )}
    >
      <Icon className="h-4 w-4 shrink-0" />
      {children}
    </Link>
  );
}

/** The header and sidebar, laid out as the firewall's own pages (cc-shell `shellFrame`). */
export function Shell() {
  const session = useSession();
  const { theme, setTheme } = useTheme();
  const [leaving, setLeaving] = useState(false);
  const dark = theme === "dark";
  return (
    <div className="flex min-h-dvh flex-col bg-bg-2 font-sans text-ink antialiased md:h-dvh">
      <StopBanner />
      <div className="grid min-h-0 flex-1 grid-rows-[58px_auto_1fr] md:grid-cols-[220px_1fr] md:grid-rows-[58px_1fr] md:overflow-hidden">
        <header className="flex min-w-0 items-center gap-3 px-4 md:col-span-2 md:px-5">
          <Brand />
          <span className="hidden truncate font-mono text-[11.5px] text-ink-2 sm:inline">firewall</span>
          <span className="flex-1" />
          <StopButton />
          <Button variant="ghost" size="icon-sm" aria-label={dark ? "Light theme" : "Dark theme"} onClick={() => setTheme(dark ? "light" : "dark")}>
            {dark ? <Sun /> : <Moon />}
          </Button>
          <Button
            variant="outline"
            size="sm"
            disabled={leaving}
            data-testid="sign-out"
            onClick={() => {
              setLeaving(true);
              void session.signOut();
            }}
          >
            <LogOut />
            <span className="hidden sm:inline">Sign out</span>
          </Button>
        </header>
        <nav aria-label="Firewall" className="flex min-w-0 gap-0.5 overflow-x-auto px-3 pb-2 md:flex-col md:overflow-x-visible md:overflow-y-auto md:pb-4">
          {NAV.map((p) => (
            <NavLink key={p.path} to={p.path} icon={p.icon}>
              {p.title}
            </NavLink>
          ))}
        </nav>
        <main className="min-w-0 border-t border-line bg-surface shadow-sm md:mr-2 md:mb-2 md:overflow-y-auto md:rounded-tl-2xl md:border">
          <div className="mx-auto w-full max-w-[1100px] px-4 py-6 sm:px-6 sm:py-8">
            <Outlet />
          </div>
        </main>
      </div>
    </div>
  );
}
