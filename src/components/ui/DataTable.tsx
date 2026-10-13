import type { ReactNode } from "react";
import { cn } from "@/lib/cn";

export interface Column<T> {
  id: string;
  header: string;
  width: string;
  mono?: boolean;
  align?: "left" | "right";
  cell: (row: T) => ReactNode;
}

interface Props<T> {
  columns: Column<T>[];
  rows: T[];
  rowKey: (row: T) => string | number;
  selectedKey?: string | number | null;
  onSelect?: (row: T) => void;
  empty?: ReactNode;
}

export const gridTemplate = <T,>(columns: Column<T>[]) => columns.map((c) => c.width).join(" ");

export function DataTable<T>({ columns, rows, rowKey, selectedKey, onSelect, empty }: Props<T>) {
  const template = gridTemplate(columns);
  return (
    <div role="table" className="flex h-full min-h-0 flex-col text-xs">
      <div role="row" className="grid shrink-0 border-b border-line bg-surface px-2" style={{ gridTemplateColumns: template }}>
        {columns.map((c) => (
          <div key={c.id} role="columnheader" className={cn("truncate px-2 py-1.5 font-medium text-muted", c.align === "right" && "text-right")}>
            {c.header}
          </div>
        ))}
      </div>
      <div className="min-h-0 flex-1 overflow-auto">
        {rows.length === 0 && empty}
        {rows.map((row) => {
          const key = rowKey(row);
          return (
            <div
              key={key}
              role="row"
              aria-selected={key === selectedKey}
              onClick={() => onSelect?.(row)}
              className={cn(
                "grid cursor-default border-b border-line/50 px-2 transition-colors duration-100 hover:bg-hover",
                key === selectedKey && "bg-primary-muted/30",
              )}
              style={{ gridTemplateColumns: template }}
            >
              {columns.map((c) => (
                <div key={c.id} role="cell" className={cn("truncate px-2 py-1.5", c.mono && "font-mono", c.align === "right" && "text-right")}>
                  {c.cell(row)}
                </div>
              ))}
            </div>
          );
        })}
      </div>
    </div>
  );
}
