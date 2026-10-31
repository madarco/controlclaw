import * as React from "react";
import { cn } from "../lib/utils";

/**
 * A native `<select>` with its own chevron. The browser's arrow is turned off (`appearance: none`)
 * and the `native-select` class in globals.css draws a chevron 10px in from the right edge, with one
 * colour for light and one for dark. `pr-8` is added last so the text never runs under it, whatever
 * padding the caller passes. Everything else (width, height, text size, border) is the caller's.
 */
export const NativeSelect = React.forwardRef<HTMLSelectElement, React.SelectHTMLAttributes<HTMLSelectElement>>(
  function NativeSelect({ className, children, ...props }, ref) {
    return (
      <select ref={ref} className={cn(className, "native-select pr-8")} {...props}>
        {children}
      </select>
    );
  },
);
