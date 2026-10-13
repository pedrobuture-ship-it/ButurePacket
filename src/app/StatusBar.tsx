import { useEffect, useState } from "react";
import { Filter } from "lucide-react";
import { StatusIndicator, type Status } from "@/components/ui";
import { useCaptureStore } from "@/stores/capture";
import { useUiStore } from "@/stores/ui";
import { formatBytes, formatCount, formatDuration, formatPercent } from "@/lib/format";

const statusOf: Record<string, { status: Status; label: string }> = {
  idle: { status: "idle", label: "Idle" },
  capturing: { status: "live", label: "Capturing" },
  paused: { status: "paused", label: "Paused" },
  processing: { status: "busy", label: "Processing" },
  error: { status: "error", label: "Error" },
};

function utcLabel(d: Date): string {
  const off = -d.getTimezoneOffset() / 60;
  const sign = off < 0 ? "-" : "+";
  return `UTC${sign}${Math.abs(off)}`;
}

function useClock() {
  const [now, setNow] = useState(() => new Date());
  useEffect(() => {
    const t = setInterval(() => setNow(new Date()), 1000);
    return () => clearInterval(t);
  }, []);
  return now;
}

export function StatusBar() {
  const { state, mode, selectedInterface, stats, error } = useCaptureStore();
  const filter = useUiStore((s) => s.filter);
  const now = useClock();
  const s = statusOf[state];
  const where = mode === "live" ? `on ${selectedInterface ?? "—"}` : "(offline)";
  return (
    <footer className="flex h-7 shrink-0 items-center gap-5 border-t border-line bg-surface px-4 font-mono text-[11px] text-muted">
      <StatusIndicator status={s.status} label={`${s.label} ${where}`} />
      <span>Duration: {formatDuration(stats.durationMs)}</span>
      <span>Packets: {formatCount(stats.packets)}</span>
      <span>
        Dropped: {formatCount(stats.dropped)}
      </span>
      <span>Buffer: {formatBytes(stats.bufferBytes)}</span>
      <span>Parser Load: {formatPercent(stats.parserLoad)}</span>
      {error && <span className="truncate text-danger">{error}</span>}
      <div className="flex-1" />
      <span className="flex items-center gap-1.5 text-primary">
        <span className="h-1.5 w-1.5 rounded-full bg-primary" />
        {mode === "live" ? "LIVE" : "OFFLINE"}
      </span>
      <span className="flex items-center gap-1.5">
        <Filter size={11} />
        {filter || "No Filters"}
      </span>
      <span>
        {utcLabel(now)} {now.toLocaleTimeString("en-GB")}
      </span>
    </footer>
  );
}
