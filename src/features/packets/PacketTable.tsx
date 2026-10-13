import { useCallback, useEffect, useLayoutEffect, useMemo, useRef, useState } from "react";
import { useVirtualizer } from "@tanstack/react-virtual";
import { ArrowDown } from "lucide-react";
import { ContextMenu, EmptyState, type ContextMenuState } from "@/components/ui";
import { formatCount } from "@/lib/format";
import { usePacketsStore } from "@/stores/packets";
import { useUiStore } from "@/stores/ui";
import type { PacketSummary } from "@/types/ipc";
import { PACKET_COLUMNS, PacketRow, ROW_HEIGHT } from "./PacketRow";
import { endpoint, packetToText } from "./packetText";
import { useStoredSearch } from "@/stores/storedSearch";
import { filterProgress, makePacketView, makeStoredView } from "./packetView";

const HEADERS = ["#", "Time", "Source", "Destination", "Protocol", "Src Port", "Dst Port", "Length", "Info"];
const FOLLOW_THRESHOLD = ROW_HEIGHT * 2;

function copy(text: string) {
  void navigator.clipboard?.writeText(text).catch(() => undefined);
}

export function PacketTable() {
  const rowCount = usePacketsStore((s) => s.count);
  const selectedId = usePacketsStore((s) => s.selectedId);
  const select = usePacketsStore((s) => s.select);
  const setInspectorOpen = usePacketsStore((s) => s.setInspectorOpen);
  const applyFilter = useUiStore((s) => s.applyFilter);
  const filterAst = useUiStore((s) => s.filterAst);
  const filtered = useUiStore((s) => s.filter !== "");
  // Filtering a very large buffer is sliced into ~8 ms steps; `tick` re-runs it until done.
  const [tick, setTick] = useState(0);
  const progress = useMemo(() => filterProgress(filterAst, rowCount, 8), [filterAst, rowCount, tick]); // eslint-disable-line react-hooks/exhaustive-deps
  useEffect(() => {
    if (progress.done) return;
    const h = setTimeout(() => setTick((t) => t + 1), 0);
    return () => clearTimeout(h);
  }, [progress, tick]);
  const stored = useStoredSearch((s) => (s.enabled ? s.rows : null));
  const view = useMemo(() => (stored ? makeStoredView(stored) : makePacketView(progress.indices, rowCount)), [stored, progress, rowCount]);
  const count = view.count;

  const scrollRef = useRef<HTMLDivElement>(null);
  const lastProgrammaticTop = useRef(-1);
  const [follow, setFollow] = useState(true);
  const [menu, setMenu] = useState<ContextMenuState | null>(null);

  const virtualizer = useVirtualizer({
    count,
    getScrollElement: () => scrollRef.current,
    estimateSize: () => ROW_HEIGHT,
    overscan: 24,
  });

  const scrollToBottom = useCallback(() => {
    const el = scrollRef.current;
    if (!el) return;
    el.scrollTop = el.scrollHeight;
    lastProgrammaticTop.current = el.scrollTop;
  }, []);

  // Stay glued to the newest packet while following.
  useLayoutEffect(() => {
    if (follow && !stored) scrollToBottom();
  }, [count, follow, stored, scrollToBottom]);

  const onScroll = () => {
    const el = scrollRef.current;
    if (!el || Math.abs(el.scrollTop - lastProgrammaticTop.current) < 2) return;
    setFollow(el.scrollHeight - el.scrollTop - el.clientHeight < FOLLOW_THRESHOLD);
  };

  const open = useCallback(
    (id: number) => {
      select(id);
      setInspectorOpen(true);
    },
    [select, setInspectorOpen],
  );

  const moveSelection = (delta: number) => {
    if (count === 0) return;
    const current = selectedId === null ? -1 : view.positionOfId(selectedId);
    const next = Math.max(0, Math.min(count - 1, current === -1 ? (delta > 0 ? 0 : count - 1) : current + delta));
    const row = view.at(next);
    if (!row) return;
    select(row.id);
    virtualizer.scrollToIndex(next, { align: "auto" });
    if (next < count - 1 && delta < 0) setFollow(false);
  };

  const onKeyDown = (e: React.KeyboardEvent) => {
    const page = Math.max(1, Math.floor((scrollRef.current?.clientHeight ?? 400) / ROW_HEIGHT) - 1);
    const handled = (() => {
      switch (e.key) {
        case "ArrowDown":
        case "j":
          return moveSelection(1), true;
        case "ArrowUp":
        case "k":
          return moveSelection(-1), true;
        case "PageDown":
          return moveSelection(page), true;
        case "PageUp":
          return moveSelection(-page), true;
        case "Home":
          return moveSelection(-count), setFollow(false), true;
        case "End":
          return moveSelection(count), setFollow(true), true;
        case "Enter":
          if (selectedId !== null) open(selectedId);
          return selectedId !== null;
        default:
          return false;
      }
    })();
    if (handled) e.preventDefault();
  };

  const onContext = useCallback(
    (e: React.MouseEvent, p: PacketSummary) => {
      e.preventDefault();
      select(p.id);
      setMenu({
        x: e.clientX,
        y: e.clientY,
        items: [
          { id: "inspect", label: "Open inspector", shortcut: ["Enter"], onSelect: () => open(p.id) },
          { id: "s1", label: "", separator: true },
          { id: "row", label: "Copy row", onSelect: () => copy(packetToText(p)) },
          { id: "src", label: "Copy source", onSelect: () => copy(endpoint(p, "src")) },
          { id: "dst", label: "Copy destination", onSelect: () => copy(endpoint(p, "dst")) },
          { id: "info", label: "Copy info", onSelect: () => copy(p.info) },
          { id: "s2", label: "", separator: true },
          { id: "fsrc", label: "Filter by source", disabled: !p.sourceIp, onSelect: () => applyFilter(`src.ip = ${p.sourceIp}`) },
          { id: "fdst", label: "Filter by destination", disabled: !p.destinationIp, onSelect: () => applyFilter(`dst.ip = ${p.destinationIp}`) },
        ],
      });
    },
    [open, select, applyFilter],
  );

  const lastVisible = virtualizer.range?.endIndex ?? count - 1;
  const unseen = follow || stored ? 0 : Math.max(0, count - 1 - lastVisible);

  return (
    <div role="table" aria-label="Packets" aria-rowcount={count} className="relative flex h-full min-h-0 flex-col">
      <div role="row" className="grid shrink-0 border-b border-line bg-surface px-2 text-xs font-medium text-muted" style={{ gridTemplateColumns: PACKET_COLUMNS, overflow: "hidden", scrollbarGutter: "stable" }}>
        {HEADERS.map((h, i) => (
          <div key={h} role="columnheader" className={i === 7 ? "px-2 py-1.5 text-right" : "px-2 py-1.5"}>
            {h}
          </div>
        ))}
      </div>
      <div ref={scrollRef} tabIndex={0} onScroll={onScroll} onKeyDown={onKeyDown} className="min-h-0 flex-1 overflow-y-auto overflow-x-hidden outline-none" style={{ scrollbarGutter: "stable" }}>
        {count === 0 ? (
          <EmptyState title={stored ? "No stored packets match" : filtered && rowCount > 0 ? "No packets match the filter" : "No packets yet"} description={stored ? "Nothing in the stored capture matches this filter." : filtered && rowCount > 0 ? "Adjust or clear the filter to see more traffic." : "Start a capture on an interface or open a PCAP file to see traffic here."} />
        ) : (
          <div className="relative w-full" style={{ height: virtualizer.getTotalSize() }}>
            {virtualizer.getVirtualItems().map((v) => {
              const p = view.at(v.index);
              if (!p) return null;
              return <PacketRow key={p.id} packet={p} selected={p.id === selectedId} top={v.start} onSelect={select} onOpen={open} onContext={onContext} />;
            })}
          </div>
        )}
      </div>
      {!stored && !progress.done && (
        <div role="status" className="absolute right-4 top-9 rounded border border-line-strong bg-raised px-2 py-1 font-mono text-[11px] text-muted">
          Filtering… {Math.floor((progress.processed / Math.max(1, rowCount)) * 100)}%
        </div>
      )}
      {unseen > 0 && (
        <button
          type="button"
          onClick={() => {
            setFollow(true);
            scrollToBottom();
          }}
          className="absolute bottom-3 left-1/2 flex -translate-x-1/2 items-center gap-1.5 rounded-full border border-primary-muted bg-raised px-3 py-1 font-mono text-xs text-primary shadow-lg animate-fade-in hover:bg-hover"
        >
          <ArrowDown size={12} />+ {formatCount(unseen)} new packets
        </button>
      )}
      <ContextMenu state={menu} onClose={() => setMenu(null)} />
    </div>
  );
}
