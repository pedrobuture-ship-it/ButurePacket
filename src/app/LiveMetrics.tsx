import { Metric } from "@/components/ui";
import { useCaptureStore } from "@/stores/capture";
import { formatCount, formatPercent, formatRate } from "@/lib/format";

export function LiveMetrics() {
  const stats = useCaptureStore((s) => s.stats);
  const dropRatio = stats.packets > 0 ? stats.dropped / (stats.packets + stats.dropped) : 0;
  return (
    <div className="flex h-full items-center gap-5 border-l border-line px-4">
      <Metric label="Packets/s" value={formatRate(stats.packetsPerSec)} />
      <Metric label="MB/s" value={(stats.bytesPerSec / 1048576).toFixed(1)} />
      <Metric label="Total packets" value={formatCount(stats.packets)} />
      <Metric
        label="Dropped"
        value={<span className={stats.dropped > 0 ? "text-danger" : undefined}>{formatCount(stats.dropped)}</span>}
        hint={`(${formatPercent(dropRatio, 3)})`}
      />
    </div>
  );
}
