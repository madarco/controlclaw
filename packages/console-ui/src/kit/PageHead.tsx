"use client";

import { createContext, useContext, type ReactNode } from "react";

/** The page help an app puts in every page head (the console: the tour's "?"), unless a page passes its own. */
const PageHelpContext = createContext<ReactNode>(null);

export function PageHelpProvider({ help, children }: { help: ReactNode; children: ReactNode }) {
  return <PageHelpContext.Provider value={help}>{children}</PageHelpContext.Provider>;
}

interface PageHeadProps {
  title: string;
  /** Optional serif italic accent shown inline after the title (e.g. the user's name). */
  serifAccent?: string;
  /** A node rather than a string: some pages put a link in the subtitle. */
  sub?: ReactNode;
  actions?: ReactNode;
  /** The page help button, first in the action row. Defaults to the `PageHelpProvider`'s. */
  help?: ReactNode;
}

/**
 * On a phone the title and description take the full width and the actions go under them, as in
 * the v2 design. Side by side, `flex-1` alone let a wide action row squeeze the description into a
 * column a word wide (the Channels page at 390px). From `sm` up the text keeps a basis, so the
 * actions still wrap under it when the row is too narrow for both.
 *
 * The page help (`help`) goes first in the action row.
 */
export function PageHead({ title, serifAccent, sub, actions, help }: PageHeadProps) {
  const appHelp = useContext(PageHelpContext);
  return (
    <div className="mb-4 flex flex-col gap-3 sm:mb-6 sm:flex-row sm:flex-wrap sm:items-start sm:gap-5">
      <div className="min-w-0 sm:flex-1 sm:basis-[20rem]">
        <h1 className="text-[23px] font-semibold leading-[1.15] tracking-[-0.025em] text-ink sm:text-[27px]">
          {title}
          {serifAccent ? (
            <>
              {" "}
              <span className="font-serif font-normal italic text-brand-ink">{serifAccent}</span>
            </>
          ) : null}
        </h1>
        {sub ? (
          <p className="mt-1 max-w-[70ch] text-[13.5px] text-ink-2 sm:mt-[7px] sm:text-[14.5px]">{sub}</p>
        ) : null}
      </div>
      {/* `empty:hidden`: on a page with no actions and no help, the button renders nothing, and the
          row must not leave a gap under the title on a phone. */}
      <div className="flex flex-wrap items-center gap-2 empty:hidden">
        {help === undefined ? appHelp : help}
        {actions}
      </div>
    </div>
  );
}
