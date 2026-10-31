import * as React from "react";
import { cva, type VariantProps } from "class-variance-authority";
import { Slot } from "radix-ui";

import { cn } from "../lib/utils";

const buttonVariants = cva(
  "inline-flex items-center justify-center gap-2 whitespace-nowrap rounded-md text-sm font-medium leading-tight transition-all cursor-pointer disabled:pointer-events-none disabled:brightness-90 [&_svg]:pointer-events-none [&_svg:not([class*='size-'])]:size-4 shrink-0 [&_svg]:shrink-0 outline-none focus-visible:border-ring focus-visible:ring-ring/50 focus-visible:ring-[3px] aria-invalid:ring-destructive/20 dark:aria-invalid:ring-destructive/40 aria-invalid:border-destructive",
  {
    variants: {
      variant: {
        default:
          "text-primary-foreground bg-primary hover:bg-[var(--brand-ink)] rounded-lg shadow-[0px_1px_2px_0px_rgba(26,26,26,0.05)] inset-shadow-[0px_-4px_4px_0px_rgba(255,255,255,0.20),0px_2px_8px_0px_rgba(255,255,255,0.25)] disabled:bg-gray-300 disabled:text-gray-500 disabled:inset-shadow-[0px_-4px_4px_0px_rgba(255,255,255,0.8),0px_2px_8px_0px_rgba(255,255,255,0.8)]",
        // `disabled:` is load-bearing: the base style only dims by brightness, which on a
        // saturated blue is invisible, so every primary action in the console — New agent, New
        // rule, Add channel — still read as live while it was refusing clicks (T-73).
        brand:
          "text-white bg-brand hover:bg-brand-ink rounded-lg shadow-[0_1px_0_rgba(255,255,255,0.18)_inset,0_4px_12px_-4px_oklch(0.52_0.18_265_/_0.4)] disabled:bg-line-2 disabled:text-ink-2 disabled:shadow-none",
        "primary-ink":
          "bg-ink text-white hover:bg-[#1f2937] rounded-lg shadow-[0_1px_0_rgba(255,255,255,0.1)_inset,0_1px_2px_rgba(0,0,0,0.1)]",
        "outline-surface":
          "bg-surface text-ink border border-line-2 hover:border-ink-2 rounded-lg",
        destructive:
          "bg-destructive text-white shadow-xs hover:bg-destructive/80 focus-visible:ring-destructive/20 dark:focus-visible:ring-destructive/40 dark:bg-destructive/60 shadow-[0px_1px_2px_0px_rgba(26,26,26,0.05)] inset-shadow-[0px_-4px_4px_0px_rgba(255,255,255,0.25),0px_2px_8px_0px_rgba(255,255,255,0.25)]",
        outline:
          "font-normal border bg-background hover:bg-accent/20 hover:border-accent-hover hover:text-accent-foreground dark:bg-input/30 dark:border-input dark:hover:bg-input/50 outline outline-1 outline-offset-[-1px] shadow-[inset_0px_-2px_4px_0px_rgba(0,0,0,0.05)]",
        secondary:
          "bg-secondary text-secondary-foreground shadow-xs hover:bg-secondary/80 shadow-[0px_1px_2px_0px_rgba(26,26,26,0.05)] inset-shadow-[0px_-4px_4px_0px_rgba(255,255,255,0.25),0px_2px_8px_0px_rgba(255,255,255,0.25)]",
        ghost: "font-normal hover:bg-accent hover:text-accent-foreground dark:hover:bg-accent-hover/50 disabled:text-muted-foreground",
        link: "text-link underline-offset-4 hover:text-link-hover hover:underline",
        border:
          "relative text-primary-foreground bg-gradient-to-b from-brand to-brand-2 rounded-lg " +
          "hover:from-brand-ink hover:to-brand " +
          "inset-shadow[0px_-1px_0.5px_0px_rgba(255,255,255,0.25),0px_1px_0.5px_0px_rgba(255,255,255,0.25)] " +
          "outline outline-2 outline-offset-[-2px] outline-brand hover:outline-brand-ink " +
          "before:content-[''] before:absolute before:inset-[3px] before:bg-brand before:rounded-[8px] before:z-[-1] hover:before:bg-brand-ink " +
          "[&>*]:relative [&>*]:z-[1] isolate",
        light: "bg-gray-100 text-gray-900 hover:bg-gray-200 border",
      },
      size: {
        default: "h-9 px-4 py-2 has-[>svg]:px-3",
        xs: "h-6 gap-1 rounded-md px-2 text-xs has-[>svg]:px-1.5 [&_svg:not([class*='size-'])]:size-3",
        sm: "h-8 rounded-md gap-1.5 px-3 has-[>svg]:px-2.5",
        lg: "h-10 rounded-md px-6 has-[>svg]:px-4",
        xl: "h-12 rounded-md px-8 has-[>svg]:px-6 text-md",
        icon: "size-9",
        "icon-xs": "size-6 rounded-md [&_svg:not([class*='size-'])]:size-3",
        "icon-sm": "size-8",
        "icon-lg": "size-10",
      },
    },
    defaultVariants: {
      variant: "default",
      size: "default",
    },
  },
);

function Button({
  className,
  variant = "default",
  size = "default",
  asChild = false,
  ...props
}: React.ComponentProps<"button"> &
  VariantProps<typeof buttonVariants> & {
    asChild?: boolean;
  }) {
  const Comp = asChild ? Slot.Root : "button";

  return <Comp data-slot="button" data-variant={variant} data-size={size} className={cn(buttonVariants({ variant, size, className }))} {...props} />;
}

export { Button, buttonVariants };
