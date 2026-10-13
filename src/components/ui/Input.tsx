import type { InputHTMLAttributes, ReactNode, Ref } from "react";
import { cn } from "@/lib/cn";

interface Props extends InputHTMLAttributes<HTMLInputElement> {
  icon?: ReactNode;
  mono?: boolean;
  invalid?: boolean;
  inputRef?: Ref<HTMLInputElement>;
}

export function Input({ icon, mono, invalid, className, inputRef, ...rest }: Props) {
  return (
    <label
      className={cn(
        "flex h-8 items-center gap-2 rounded border bg-surface px-2.5 text-muted transition-colors duration-150",
        "focus-within:border-primary-muted",
        invalid ? "border-danger/70" : "border-line-strong",
        className,
      )}
    >
      {icon}
      <input
        ref={inputRef}
        spellCheck={false}
        autoComplete="off"
        {...rest}
        className={cn(
          "min-w-0 flex-1 bg-transparent text-fg outline-none placeholder:text-faint select-text",
          mono ? "font-mono text-xs" : "text-[13px]",
        )}
      />
    </label>
  );
}
