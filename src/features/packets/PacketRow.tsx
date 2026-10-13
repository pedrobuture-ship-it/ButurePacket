import { memo } from "react";
import { Badge } from "@/components/ui";
import { cn } from "@/lib/cn";
import { formatCount, formatTimestamp } from "@/lib/format";
import { protocolTone } from "@/lib/protocolColors";
import type { PacketSummary } from "@/types/ipc";
import { endpoint, protocolLabel } from "./packetText";

export const ROW_HEIGHT = 24;
export const PACKET_COLUMNS = "64px 96px minmax(100px,1fr) minmax(100px,1fr) 84px 64px 64px 60px minmax(120px,2.4fr)";

interface Props {
  packet: PacketSummary;
  selected: boolean;
  top: number;
  onSelect: (id: number) => void;
  onOpen: (id: number) => void;
  onContext: (e: React.MouseEvent, p: PacketSummary) => void;
}

function Row({ packet: p, selected, top, onSelect, onOpen, onContext }: Props) {
  const label = protocolLabel(p);
  return (
    <div
      role="row"
      aria-selected={selected}
      data-id={p.id}
      onClick={() => onSelect(p.id)}
      onDoubleClick={() => onOpen(p.id)}
      onContextMenu={(e) => onContext(e, p)}
      className={cn(
        "absolute left-0 grid w-full items-center border-b border-line/40 px-2 font-mono text-xs",
        selected ? "bg-primary-muted/40 text-fg" : "text-fg/90 hover:bg-hover",
        p.issues.length > 0 && !selected && "text-warning/90",
      )}
      style={{ height: ROW_HEIGHT, transform: `translateY(${top}px)`, gridTemplateColumns: PACKET_COLUMNS }}
    >
      <span className="px-2 text-muted">{p.id}</span>
      <span className="px-2">{formatTimestamp(p.timestamp)}</span>
      <span className="truncate px-2">{endpoint(p, "src")}</span>
      <span className="truncate px-2">{endpoint(p, "dst")}</span>
      <span className="px-2">
        <Badge tone={protocolTone(label)}>{label}</Badge>
      </span>
      <span className="px-2 text-muted">{p.sourcePort ?? ""}</span>
      <span className="px-2 text-muted">{p.destinationPort ?? ""}</span>
      <span className="px-2 text-right">{formatCount(p.capturedLength)}</span>
      <span className="truncate px-2 text-muted">{p.info}</span>
    </div>
  );
}

/** Memoised so a selection change or new batch only re-renders rows whose props changed. */
export const PacketRow = memo(Row);
