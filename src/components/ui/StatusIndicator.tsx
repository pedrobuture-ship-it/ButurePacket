import { cn } from "@/lib/cn";

export type Status = "idle" | "live" | "paused" | "busy" | "error";

const dot: Record<Status, string> = {
  idle: "bg-faint",
  live: "bg-primary",
  paused: "bg-warning",
  busy: "bg-info",
  error: "bg-danger",
};

export function StatusIndicator({ status, label }: { status: Status; label?: string }) {
  return (
    <span className="inline-flex items-center gap-1.5 text-xs text-muted">
      <span className={cn("h-2 w-2 rounded-full", dot[status], (status === "live" || status === "busy") && "animate-pulse")} />
      {label}
    </span>
  );
}
