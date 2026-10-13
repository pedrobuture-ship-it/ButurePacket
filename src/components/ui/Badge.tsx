import type { ReactNode } from "react";
import { cn } from "@/lib/cn";

export type BadgeTone = "neutral" | "primary" | "danger" | "warning" | "info" | "success";

const tones: Record<BadgeTone, string> = {
  neutral: "bg-raised text-muted border-line-strong",
  primary: "bg-primary/15 text-primary border-primary-muted",
  success: "bg-success/15 text-success border-primary-muted",
  danger: "bg-danger/15 text-danger border-danger/50",
  warning: "bg-warning/15 text-warning border-warning/50",
  info: "bg-info/15 text-info border-info/50",
};

export function Badge({ tone = "neutral", mono = true, children }: { tone?: BadgeTone; mono?: boolean; children: ReactNode }) {
  return (
    <span
      className={cn(
        "inline-flex h-[18px] items-center rounded-sm border px-1.5 text-[10px] font-semibold uppercase leading-none tracking-wide",
        mono && "font-mono",
        tones[tone],
      )}
    >
      {children}
    </span>
  );
}
