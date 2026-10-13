import { cn } from "@/lib/cn";
import { sanitizeText } from "@/lib/sanitize";
import { useCaptureStore } from "@/stores/capture";

/** Makes it unmistakable whether the data on screen is a live capture or an opened file. */
export function ModeBadge({ className }: { className?: string }) {
  const mode = useCaptureStore((s) => s.mode);
  const state = useCaptureStore((s) => s.state);
  const fileName = useCaptureStore((s) => s.fileName);
  const live = mode === "live";
  const active = state === "capturing" || state === "processing";
  return (
    <span
      className={cn("inline-flex items-center gap-1.5 rounded-sm border px-1.5 py-0.5 font-mono text-[10px] font-semibold uppercase tracking-wider", live ? "border-primary-muted bg-primary-muted/20 text-primary" : "border-info/50 bg-info/10 text-info", className)}
      title={live ? "Data comes from a live capture" : `Data comes from ${sanitizeText(fileName ?? "a capture file")}`}
    >
      <span className={cn("h-1.5 w-1.5 rounded-full", live ? "bg-primary" : "bg-info", live && active && "animate-pulse")} />
      {live ? "Live capture" : "Offline capture"}
    </span>
  );
}
