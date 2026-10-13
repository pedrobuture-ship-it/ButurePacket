import { useEffect, useState } from "react";
import { ChevronDown, ChevronRight } from "lucide-react";
import { EmptyState, ResizablePanel } from "@/components/ui";
import { api } from "@/lib/api";
import { describeError, type AppError } from "@/lib/errors";
import { cn } from "@/lib/cn";
import { sanitizeText } from "@/lib/sanitize";
import { usePacketsStore } from "@/stores/packets";
import type { PacketDetail, PacketSection } from "@/types/ipc";
import { HexViewer } from "./HexViewer";
import type { ByteRange } from "./hex";

type Load = { id: number; detail: PacketDetail } | { id: number; error: AppError };

function SectionView({ section, open, onToggle, highlight, onHighlight }: { section: PacketSection; open: boolean; onToggle: () => void; highlight: ByteRange | null; onHighlight: (r: ByteRange | null) => void }) {
  const range = section.offset !== null ? { offset: section.offset, length: section.length } : null;
  return (
    <section className="border-b border-line">
      <button
        type="button"
        aria-expanded={open}
        onClick={() => {
          onToggle();
          onHighlight(range);
        }}
        className="flex h-8 w-full items-center gap-2 px-3 text-left text-[13px] font-medium text-fg transition-colors duration-150 hover:bg-hover"
      >
        {open ? <ChevronDown size={14} className="text-muted" /> : <ChevronRight size={14} className="text-muted" />}
        {section.title}
      </button>
      {open && (
        <dl className="selectable grid grid-cols-[minmax(110px,40%)_1fr] gap-x-3 gap-y-0.5 px-4 pb-2.5 text-xs">
          {section.fields.map((f, i) => {
            const active = f.offset !== null && highlight?.offset === f.offset && highlight.length === f.length;
            const clickable = f.offset !== null && f.length > 0;
            return (
              <div
                key={`${f.name}-${i}`}
                role={clickable ? "button" : undefined}
                tabIndex={clickable ? 0 : undefined}
                onClick={clickable ? () => onHighlight({ offset: f.offset!, length: f.length }) : undefined}
                onKeyDown={clickable ? (e) => e.key === "Enter" && onHighlight({ offset: f.offset!, length: f.length }) : undefined}
                className={cn("col-span-2 grid grid-cols-subgrid rounded-sm px-1 py-0.5", clickable && "cursor-pointer hover:bg-hover", active && "bg-primary-muted/40")}
              >
                <dt className="truncate text-muted">{f.name}</dt>
                <dd className="break-all font-mono text-fg">{sanitizeText(f.value)}</dd>
              </div>
            );
          })}
        </dl>
      )}
    </section>
  );
}

export function PacketInspector() {
  const selectedId = usePacketsStore((s) => s.selectedId);
  const [load, setLoad] = useState<Load | null>(null);
  const [closed, setClosed] = useState<Set<string>>(new Set());
  const [highlight, setHighlight] = useState<ByteRange | null>(null);

  useEffect(() => {
    if (selectedId === null) return;
    let cancelled = false;
    api
      .getPacketDetail(selectedId)
      .then((detail) => !cancelled && (setLoad({ id: selectedId, detail }), setHighlight(null)))
      .catch((e) => !cancelled && setLoad({ id: selectedId, error: describeError(e) }));
    return () => {
      cancelled = true;
    };
  }, [selectedId]);

  if (selectedId === null) return <EmptyState title="No packet selected" description="Select a packet to inspect its layers and bytes." />;
  if (!load || load.id !== selectedId) return <EmptyState title="Loading packet…" />;
  if ("error" in load) return <EmptyState title="Packet unavailable" description={[load.error.message, load.error.hint].filter(Boolean).join(" ")} />;

  const { detail } = load;
  return (
    <div className="flex h-full min-h-0 flex-col">
      <div className="flex h-8 shrink-0 items-center border-b border-line px-3 text-[11px] font-semibold uppercase tracking-wider text-muted">
        Packet Details <span className="ml-2 font-mono normal-case text-faint">#{selectedId}</span>
      </div>
      <div className="min-h-0 flex-1 overflow-auto">
        {detail.sections.map((s) => (
          <SectionView
            key={s.id}
            section={s}
            open={!closed.has(s.id)}
            highlight={highlight}
            onHighlight={setHighlight}
            onToggle={() =>
              setClosed((prev) => {
                const next = new Set(prev);
                if (!next.delete(s.id)) next.add(s.id);
                return next;
              })
            }
          />
        ))}
      </div>
      <ResizablePanel id="hex-viewer" side="top" defaultSize={230} min={90} max={520} className="border-t border-line-strong bg-bg">
        <HexViewer bytes={detail.bytes} highlight={highlight} />
      </ResizablePanel>
    </div>
  );
}
