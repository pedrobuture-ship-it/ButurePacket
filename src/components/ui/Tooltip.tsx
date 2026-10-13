import { useId, useState, type ReactNode } from "react";
import { cn } from "@/lib/cn";

interface Props {
  label: string;
  children: ReactNode;
  side?: "top" | "bottom" | "right";
}

export function Tooltip({ label, children, side = "bottom" }: Props) {
  const [open, setOpen] = useState(false);
  const id = useId();
  return (
    <span
      className="relative inline-flex"
      onMouseEnter={() => setOpen(true)}
      onMouseLeave={() => setOpen(false)}
      onFocus={() => setOpen(true)}
      onBlur={() => setOpen(false)}
      aria-describedby={open ? id : undefined}
    >
      {children}
      {open && (
        <span
          id={id}
          role="tooltip"
          className={cn(
            "pointer-events-none absolute z-50 whitespace-nowrap rounded border border-line-strong bg-raised px-2 py-1 text-[11px] text-fg animate-fade-in",
            side === "bottom" && "left-1/2 top-full mt-1.5 -translate-x-1/2",
            side === "top" && "bottom-full left-1/2 mb-1.5 -translate-x-1/2",
            side === "right" && "left-full top-1/2 ml-1.5 -translate-y-1/2",
          )}
        >
          {label}
        </span>
      )}
    </span>
  );
}
