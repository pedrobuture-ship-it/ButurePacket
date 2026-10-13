import type { ReactNode } from "react";
import { cn } from "@/lib/cn";

interface Props {
  title?: string;
  actions?: ReactNode;
  children: ReactNode;
  className?: string;
  bodyClassName?: string;
}

export function Panel({ title, actions, children, className, bodyClassName }: Props) {
  return (
    <section className={cn("flex min-h-0 min-w-0 flex-col rounded border border-line bg-surface", className)}>
      {(title || actions) && (
        <header className="flex h-8 shrink-0 items-center justify-between border-b border-line px-3">
          <h2 className="text-[11px] font-semibold uppercase tracking-wider text-muted">{title}</h2>
          <div className="flex items-center gap-1">{actions}</div>
        </header>
      )}
      <div className={cn("min-h-0 flex-1", bodyClassName)}>{children}</div>
    </section>
  );
}
