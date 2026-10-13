import type { ButtonHTMLAttributes, ReactNode } from "react";
import { cn } from "@/lib/cn";
import { Tooltip } from "./Tooltip";

interface Props extends Omit<ButtonHTMLAttributes<HTMLButtonElement>, "aria-label"> {
  label: string;
  children: ReactNode;
  active?: boolean;
  tooltipSide?: "top" | "bottom" | "right";
}

export function IconButton({ label, children, active, className, tooltipSide, ...rest }: Props) {
  return (
    <Tooltip label={label} side={tooltipSide}>
      <button
        type="button"
        aria-label={label}
        aria-pressed={active}
        {...rest}
        className={cn(
          "inline-flex h-8 w-8 items-center justify-center rounded border border-transparent text-muted transition-colors duration-150",
          "hover:bg-hover hover:text-fg disabled:cursor-not-allowed disabled:opacity-40",
          active && "border-line-strong bg-raised text-primary",
          className,
        )}
      >
        {children}
      </button>
    </Tooltip>
  );
}
