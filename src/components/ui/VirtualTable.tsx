import { useRef, type ReactNode } from "react";
import { useVirtualizer } from "@tanstack/react-virtual";
import { cn } from "@/lib/cn";

export interface VColumn<T> {
  id: string;
  header: string;
  width: string;
  mono?: boolean;
  align?: "left" | "right";
  cell: (row: T) => ReactNode;
}

interface Props<T> {
  columns: VColumn<T>[];
  rows: T[];
  rowKey: (row: T) => string | number;
  rowHeight?: number;
  selectedKey?: string | number | null;
  onSelect?: (row: T) => void;
  onContextMenu?: (event: React.MouseEvent, row: T) => void;
  empty?: ReactNode;
  label: string;
}

/** Generic virtualized table for large, read-mostly lists. */
export function VirtualTable<T>({ columns, rows, rowKey, rowHeight = 26, selectedKey, onSelect, onContextMenu, empty, label }: Props<T>) {
  const ref = useRef<HTMLDivElement>(null);
  const virtualizer = useVirtualizer({ count: rows.length, getScrollElement: () => ref.current, estimateSize: () => rowHeight, overscan: 16 });
  const template = columns.map((c) => c.width).join(" ");
  return (
    <div role="table" aria-label={label} aria-rowcount={rows.length} className="flex h-full min-h-0 flex-col">
      <div role="row" className="grid shrink-0 border-b border-line bg-surface px-2 text-xs font-medium text-muted" style={{ gridTemplateColumns: template, overflow: "hidden", scrollbarGutter: "stable" }}>
        {columns.map((c) => (
          <div key={c.id} role="columnheader" className={cn("px-2 py-1.5", c.align === "right" && "text-right")}>
            {c.header}
          </div>
        ))}
      </div>
      <div ref={ref} className="min-h-0 flex-1 overflow-y-auto overflow-x-hidden" style={{ scrollbarGutter: "stable" }}>
        {rows.length === 0 ? (
          empty
        ) : (
          <div className="relative w-full" style={{ height: virtualizer.getTotalSize() }}>
            {virtualizer.getVirtualItems().map((v) => {
              const row = rows[v.index];
              const key = rowKey(row);
              return (
                <div
                  key={key}
                  role="row"
                  aria-selected={key === selectedKey}
                  onClick={() => onSelect?.(row)}
                  onContextMenu={onContextMenu ? (e) => onContextMenu(e, row) : undefined}
                  className={cn("absolute left-0 grid w-full items-center border-b border-line/40 px-2 text-xs", key === selectedKey ? "bg-primary-muted/40" : "hover:bg-hover")}
                  style={{ height: rowHeight, transform: `translateY(${v.start}px)`, gridTemplateColumns: template }}
                >
                  {columns.map((c) => (
                    <span key={c.id} role="cell" className={cn("truncate px-2", c.mono && "font-mono", c.align === "right" && "text-right")}>
                      {c.cell(row)}
                    </span>
                  ))}
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}
