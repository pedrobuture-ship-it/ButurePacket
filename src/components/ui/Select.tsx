import type { SelectHTMLAttributes } from "react";
import { ChevronDown } from "lucide-react";
import { cn } from "@/lib/cn";

interface Props extends SelectHTMLAttributes<HTMLSelectElement> {
  options: { value: string; label: string }[];
}

export function Select({ options, className, ...rest }: Props) {
  return (
    <span className="relative inline-flex">
      <select
        {...rest}
        className={cn(
          "h-8 appearance-none rounded border border-line-strong bg-surface pl-2.5 pr-7 text-[13px] text-fg",
          "transition-colors duration-150 hover:bg-hover focus:border-primary-muted",
          className,
        )}
      >
        {options.map((o) => (
          <option key={o.value} value={o.value}>
            {o.label}
          </option>
        ))}
      </select>
      <ChevronDown size={14} className="pointer-events-none absolute right-2 top-2.5 text-muted" />
    </span>
  );
}
