import type { ReactNode } from "react";
import { Brand } from "../shell/Brand";

/** The narrow card the sign-in screens sit in, like the firewall's own minimal pages. */
export function AuthFrame({ title, sub, children }: { title: string; sub?: ReactNode; children: ReactNode }) {
  return (
    <div className="min-h-dvh bg-bg-2 font-sans text-ink antialiased">
      <div className="mx-auto w-full max-w-[30rem] px-4 pt-6 pb-12 sm:pt-12">
        <div className="mb-5">
          <Brand />
        </div>
        <main className="min-w-0 rounded-2xl border border-line bg-surface p-5 shadow-sm sm:p-8">
          <h1 className="text-[21px] font-semibold tracking-[-0.02em] text-ink">{title}</h1>
          {sub ? <p className="mt-1.5 text-[13.5px] text-ink-2">{sub}</p> : null}
          <div className="mt-5">{children}</div>
        </main>
      </div>
    </div>
  );
}

export function FormError({ children }: { children: ReactNode }) {
  return children ? (
    <p role="alert" className="text-[13px] text-block">
      {children}
    </p>
  ) : null;
}
