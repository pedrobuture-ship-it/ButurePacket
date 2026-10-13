import { FileUp, X } from "lucide-react";
import { Button, IconButton } from "@/components/ui";
import { cn } from "@/lib/cn";
import { captureActions } from "@/lib/captureActions";
import { formatBytes, formatCount } from "@/lib/format";
import { sanitizeText } from "@/lib/sanitize";
import { useCaptureStore } from "@/stores/capture";
import { useNoticeStore } from "@/stores/notices";
import { useUiStore } from "@/stores/ui";

/** Shown while a capture file is being read. */
export function OpenProgressCard() {
  const p = useCaptureStore((s) => s.openProgress);
  if (!p) return null;
  const counting = p.phase === "counting";
  const total = p.total ?? 0;
  const done = p.processed ?? 0;
  const fraction = counting ? (p.fileBytes ? 0 : 0) : total > 0 ? Math.min(1, done / total) : p.fileBytes ? Math.min(1, (p.bytesRead ?? 0) / p.fileBytes) : 0;
  return (
    <div role="status" aria-live="polite" className="fixed bottom-12 left-1/2 z-40 w-[420px] -translate-x-1/2 rounded border border-line-strong bg-raised p-4 shadow-2xl animate-pop-in">
      <div className="mb-1 flex items-center justify-between">
        <span className="text-[13px] font-medium">{counting ? "Reading Capture" : "Parsing Capture"}</span>
        <span className="max-w-[200px] truncate font-mono text-[11px] text-muted" title={sanitizeText(p.fileName)}>
          {sanitizeText(p.fileName)}
        </span>
      </div>
      <p className="font-mono text-xs text-fg">{counting ? `Scanning ${p.fileBytes ? formatBytes(p.fileBytes) : "file"}…` : `${formatCount(done)} / ${formatCount(total)} packets`}</p>
      <div className="my-3 h-1.5 overflow-hidden rounded bg-bg" role="progressbar" aria-valuemin={0} aria-valuemax={100} aria-valuenow={Math.round(fraction * 100)}>
        <div className={cn("h-full bg-primary transition-[width] duration-150", counting && "w-1/3 animate-pulse")} style={counting ? undefined : { width: `${fraction * 100}%` }} />
      </div>
      <div className="flex justify-end">
        <Button size="sm" variant="danger" onClick={captureActions.cancelOpen}>
          Cancel
        </Button>
      </div>
    </div>
  );
}

export function DropOverlay() {
  const dragging = useUiStore((s) => s.dragging);
  if (!dragging) return null;
  return (
    <div className="pointer-events-none fixed inset-0 z-50 flex items-center justify-center bg-bg/80 animate-fade-in">
      <div className="flex flex-col items-center gap-3 rounded border-2 border-dashed border-primary px-16 py-12 text-primary">
        <FileUp size={36} />
        <p className="text-sm font-medium">Drop a PCAP or PCAPNG file to analyse it</p>
      </div>
    </div>
  );
}

const TONE = { info: "border-info/50", success: "border-primary-muted", warning: "border-warning/60", error: "border-danger/60" } as const;

export function Notices() {
  const notices = useNoticeStore((s) => s.notices);
  const dismiss = useNoticeStore((s) => s.dismiss);
  if (notices.length === 0) return null;
  return (
    <div role="log" aria-live="polite" className="fixed bottom-10 right-4 z-50 flex w-[360px] flex-col gap-2">
      {notices.map((n) => (
        <div key={n.id} role={n.tone === "error" ? "alert" : "status"} className={cn("flex items-start gap-2 rounded border bg-raised px-3 py-2 text-xs shadow-xl animate-slide-in", TONE[n.tone])}>
          <p className="flex-1 select-text text-fg">{n.text}</p>
          <IconButton label="Dismiss" className="h-5 w-5" onClick={() => dismiss(n.id)}>
            <X size={12} />
          </IconButton>
        </div>
      ))}
    </div>
  );
}
