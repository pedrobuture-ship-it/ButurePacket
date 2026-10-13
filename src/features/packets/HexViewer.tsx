import { memo, useEffect, useRef } from "react";
import { useVirtualizer } from "@tanstack/react-virtual";
import { cn } from "@/lib/cn";
import { asciiChar } from "@/lib/sanitize";
import { BYTES_PER_ROW, type ByteRange, formatOffset, hexByte, inRange, rowOfOffset } from "./hex";

const ROW_H = 18;

interface Props {
  bytes: number[];
  highlight: ByteRange | null;
}

const HexRow = memo(function HexRow({ bytes, row, highlight, top }: { bytes: number[]; row: number; highlight: ByteRange | null; top: number }) {
  const start = row * BYTES_PER_ROW;
  const slice = bytes.slice(start, start + BYTES_PER_ROW);
  return (
    <div className="absolute left-0 flex w-full whitespace-pre px-2" style={{ transform: `translateY(${top}px)`, height: ROW_H }}>
      <span className="w-[64px] shrink-0 text-muted">{formatOffset(start)}</span>
      <span className="w-[316px] shrink-0">
        {slice.map((b, i) => (
          <span key={i} className={cn("inline-block w-[19px]", i === 7 && "mr-2", inRange(start + i, highlight) && "rounded-sm bg-primary text-bg")}>
            {hexByte(b)}
          </span>
        ))}
      </span>
      <span className="text-muted">
        {slice.map((b, i) => (
          <span key={i} className={cn(inRange(start + i, highlight) && "rounded-sm bg-primary text-bg")}>
            {asciiChar(b)}
          </span>
        ))}
      </span>
    </div>
  );
});

export function HexViewer({ bytes, highlight }: Props) {
  const ref = useRef<HTMLDivElement>(null);
  const rows = Math.ceil(bytes.length / BYTES_PER_ROW);
  const virtualizer = useVirtualizer({ count: rows, getScrollElement: () => ref.current, estimateSize: () => ROW_H, overscan: 8 });

  useEffect(() => {
    if (highlight && highlight.length > 0) virtualizer.scrollToIndex(rowOfOffset(highlight.offset), { align: "auto" });
  }, [highlight, virtualizer]);

  return (
    <div className="flex h-full min-h-0 flex-col font-mono text-[11px] leading-[18px]">
      <div className="flex shrink-0 border-b border-line px-2 py-1 text-muted">
        <span className="w-[64px]">OFFSET</span>
        <span className="w-[316px]">HEX</span>
        <span>ASCII</span>
      </div>
      <div ref={ref} className="selectable min-h-0 flex-1 overflow-auto">
        <div className="relative" style={{ height: virtualizer.getTotalSize(), width: 64 + 316 + 16 * 7 + 24 }}>
          {virtualizer.getVirtualItems().map((v) => (
            <HexRow key={v.index} bytes={bytes} row={v.index} highlight={highlight} top={v.start} />
          ))}
        </div>
      </div>
    </div>
  );
}
