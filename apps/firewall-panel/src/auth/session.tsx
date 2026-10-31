import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { fw, watchSignedOut } from "../api/client";

/**
 * Where the person stands with this firewall: no admin yet (`setup`), signed out, signed out by
 * the firewall while using the panel (`expired`), or signed in. `firstRun` keeps the setup wizard
 * open after the password is set, for its optional steps.
 */
export type SessionState = "loading" | "unreachable" | "setup" | "signedOut" | "expired" | "admin";

interface Session {
  state: SessionState;
  firstRun: boolean;
  /** The password was set: the wizard goes on to its next steps. */
  setUp(): void;
  finishFirstRun(): void;
  signedIn(): void;
  signOut(): Promise<void>;
  retry(): void;
}

const SessionContext = createContext<Session | null>(null);

export function SessionProvider({ children }: { children: ReactNode }) {
  const qc = useQueryClient();
  const q = useQuery({ queryKey: ["session"], queryFn: () => fw.get("/api/session"), retry: 1, staleTime: Infinity });
  const [expired, setExpired] = useState(false);
  const [firstRun, setFirstRun] = useState(false);

  useEffect(() => {
    watchSignedOut(() => {
      setExpired(true);
      setFirstRun(false);
      qc.setQueryData(["session"], { admin: false, setup: false, csrf: null });
    });
  }, [qc]);

  const signedIn = useCallback(() => {
    setExpired(false);
    // Drop what the last session read; the new one reads it again.
    qc.removeQueries({ predicate: (query) => query.queryKey[0] !== "session" });
    qc.setQueryData(["session"], { admin: true, setup: false, csrf: fw.csrf() });
  }, [qc]);

  const { data: d, isPending, refetch } = q;
  const value = useMemo<Session>(() => {
    const state: SessionState = isPending
      ? "loading"
      : !d
        ? "unreachable"
        : d.setup
          ? "setup"
          : d.admin
            ? "admin"
            : expired
              ? "expired"
              : "signedOut";
    return {
      state,
      firstRun,
      setUp: () => {
        setFirstRun(true);
        signedIn();
      },
      finishFirstRun: () => setFirstRun(false),
      signedIn,
      signOut: async () => {
        await fw.post("/api/logout").catch(() => {});
        setExpired(false);
        qc.removeQueries({ predicate: (query) => query.queryKey[0] !== "session" });
        qc.setQueryData(["session"], { admin: false, setup: false, csrf: null });
      },
      retry: () => void refetch(),
    };
  }, [d, isPending, refetch, expired, firstRun, signedIn, qc]);

  return <SessionContext.Provider value={value}>{children}</SessionContext.Provider>;
}

export function useSession(): Session {
  const s = useContext(SessionContext);
  if (!s) throw new Error("useSession: no SessionProvider");
  return s;
}
