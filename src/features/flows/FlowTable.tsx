import { useMemo, useRef } from "react";
import { useVirtualizer } from "@tanstack/react-virtual";
import { Badge, EmptyState } from "@/components/ui";
import { cn } from "@/lib/cn";
import { formatBytes, formatCount, formatLatency, formatSpan } from "@/lib/format";
import { protocolTone } from "@/lib/protocolColors";
import type { FlowView } from "@/types/ipc";
import { endpointText, flowProtocolLabel } from "./flowText";

const ROW = 26;
const COLS = "minmax(104px,1.2fr) minmax(104px,1.2fr) 74px minmax(90px,1fr) 64px 66px 74px 74px 70px 100px";
const HEADERS = ["Source", "Destination", "Protocol", "Domain", "Duration", "Packets", "Upload", "Download", "Latency", "State"];

interface Props {
  flows: FlowView[];
  selectedId: number | null;
  onSelect: (id: number) => void;
}

export function FlowTable({ flows, selectedId, onSelect }: Props) {
  const ref = useRef<HTMLDivElement>(null);
  const virtualizer = useVirtualizer({ count: flows.length, getScrollElement: () => ref.current, estimateSize: () => ROW, overscan: 16 });
  const selectedIndex = useMemo(() => flows.findIndex((f) => f.id === selectedId), [flows, selectedId]);

  const onKeyDown = (e: React.KeyboardEvent) => {
    const delta = e.key === "ArrowDown" || e.key === "j" ? 1 : e.key === "ArrowUp" || e.key === "k" ? -1 : 0;
    if (!delta || flows.length === 0) return;
    e.preventDefault();
    const next = Math.max(0, Math.min(flows.length - 1, (selectedIndex === -1 ? (delta > 0 ? -1 : flows.length) : selectedIndex) + delta));
    onSelect(flows[next].id);
    virtualizer.scrollToIndex(next, { align: "auto" });
  };

  return (
    <div role="table" aria-label="Flows" aria-rowcount={flows.length} className="flex h-full min-h-0 flex-col">
      <div role="row" className="grid shrink-0 border-b border-line bg-surface px-2 text-xs font-medium text-muted" style={{ gridTemplateColumns: COLS, overflow: "hidden", scrollbarGutter: "stable" }}>
        {HEADERS.map((h) => (
          <div key={h} role="columnheader" className="px-2 py-1.5">
            {h}
          </div>
        ))}
      </div>
      <div ref={ref} tabIndex={0} onKeyDown={onKeyDown} className="min-h-0 flex-1 overflow-y-auto overflow-x-hidden outline-none" style={{ scrollbarGutter: "stable" }}>
        {flows.length === 0 ? (
          <EmptyState title="No flows yet" description="Flows appear as soon as packets between two endpoints are captured." />
        ) : (
          <div className="relative w-full" style={{ height: virtualizer.getTotalSize() }}>
            {virtualizer.getVirtualItems().map((v) => {
              const f = flows[v.index];
              const selected = f.id === selectedId;
              return (
                <div
                  key={f.id}
                  role="row"
                  aria-selected={selected}
                  onClick={() => onSelect(f.id)}
                  className={cn("absolute left-0 grid w-full items-center border-b border-line/40 px-2 font-mono text-xs", selected ? "bg-primary-muted/40" : "hover:bg-hover")}
                  style={{ height: ROW, transform: `translateY(${v.start}px)`, gridTemplateColumns: COLS }}
                >
                  <span className="truncate px-2">{endpointText(f.endpointA)}</span>
                  <span className="truncate px-2">{endpointText(f.endpointB)}</span>
                  <span className="px-2">
                    <Badge tone={protocolTone(flowProtocolLabel(f))}>{flowProtocolLabel(f)}</Badge>
                  </span>
                  <span className="truncate px-2 text-muted">{f.tls?.sni ?? f.domains[0] ?? "—"}</span>
                  <span className="px-2">{formatSpan(f.duration)}</span>
                  <span className="px-2">{formatCount(f.totalPackets)}</span>
                  <span className="px-2">{formatBytes(f.bytesAToB)}</span>
                  <span className="px-2">{formatBytes(f.bytesBToA)}</span>
                  <span className="px-2">{formatLatency(f.latency)}</span>
                  <span className={cn("truncate px-2", f.tcpState === "RESET" ? "text-danger" : "text-muted")}>{f.tcpState ?? "—"}</span>
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}
