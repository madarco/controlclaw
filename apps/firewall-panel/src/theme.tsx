import { createContext, useCallback, useContext, useState, type ReactNode } from "react";

/**
 * Light or dark, kept in `localStorage.theme` as the console keeps it. The class is set from
 * `panel.js` before React renders (`applyTheme` in main.tsx), so the page needs no inline script,
 * which its CSP refuses (next-themes writes one).
 */
export type Theme = "light" | "dark";

const KEY = "theme";

export function savedTheme(): Theme {
  try {
    return localStorage.getItem(KEY) === "dark" ? "dark" : "light";
  } catch {
    return "light";
  }
}

export function applyTheme(t: Theme): void {
  const root = document.documentElement;
  root.classList.toggle("dark", t === "dark");
  root.style.colorScheme = t;
}

const ThemeContext = createContext<{ theme: Theme; setTheme: (t: Theme) => void } | null>(null);

export function ThemeProvider({ children }: { children: ReactNode }) {
  const [theme, set] = useState<Theme>(savedTheme);
  const setTheme = useCallback((t: Theme) => {
    applyTheme(t);
    try {
      localStorage.setItem(KEY, t);
    } catch {
      // A private window: the choice lasts until the page closes.
    }
    set(t);
  }, []);
  return <ThemeContext.Provider value={{ theme, setTheme }}>{children}</ThemeContext.Provider>;
}

export function useTheme() {
  const t = useContext(ThemeContext);
  if (!t) throw new Error("useTheme: no ThemeProvider");
  return t;
}
