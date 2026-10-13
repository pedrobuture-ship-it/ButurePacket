import type { ButtonHTMLAttributes, ReactNode } from "react";
import { cn } from "@/lib/cn";

export type ButtonVariant = "primary" | "secondary" | "ghost" | "danger";

interface Props extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: ButtonVariant;
  size?: "sm" | "md";
  icon?: ReactNode;
}

const variants: Record<ButtonVariant, string> = {
  primary: "bg-primary text-bg hover:bg-primary/90 border-primary",
  secondary: "bg-raised text-fg border-line-strong hover:bg-hover",
  ghost: "bg-transparent text-muted border-transparent hover:bg-hover hover:text-fg",
  danger: "bg-danger/15 text-danger border-danger/50 hover:bg-danger/25",
};

export function Button({ variant = "secondary", size = "md", icon, className, children, ...rest }: Props) {
  return (
    <button
      type="button"
      {...rest}
      className={cn(
        "inline-flex items-center justify-center gap-2 rounded border font-medium transition-colors duration-150",
        "disabled:cursor-not-allowed disabled:opacity-40",
        size === "sm" ? "h-7 px-2.5 text-xs" : "h-8 px-3 text-[13px]",
        variants[variant],
        className,
      )}
    >
      {icon}
      {children}
    </button>
  );
}
