import { useMemo } from "react";
import { Activity, Maximize2, X } from "lucide-react";
import { Badge, Button, EmptyState, IconButton, Input, VirtualTable, type BadgeTone, type VColumn } from "@/components/ui";
import { cn } from "@/lib/cn";
import { sanitizeText } from "@/lib/sanitize";
import { EventSubject } from "@/lib/filter/adapters";
import { filterItems } from "@/lib/filter/apply";
import { useUiStore } from "@/stores/ui";
import { eventBuffer, useEventsStore } from "@/stores/events";
import { useCaptureStore } from "@/stores/capture";
import { ALL_GROUPS, useTimelineStore } from "@/stores/timeline";
import type { EventKind, TimelineEvent } from "@/types/ipc";
import { TimelineChart } from "./TimelineChart";
import { GROUPS, formatClock, groupOf, lowerBound, matchesFilter, type Range } from "./model";

const AUTO_FOLLOW_SPAN = 60_000_000; // while capturing, show the latest minute

const tone = (k: EventKind): BadgeTone => {
  switch (groupOf(k)) {
    case "dns":
      return k === "dnsFailure" ? "danger" : "info";
    case "tls":
      return "primary";
    case "problems":
      return k === "reset" ? "danger" : "warning";
    case "traffic":
      return "warning";
    default:
      return "success";
  }
};

const columns: VColumn<TimelineEvent>[] = [
  { id: "time", header: "Time", width: "104px", mono: true, cell: (e) => formatClock(e.ts, true) },
  { id: "type", header: "Type", width: "96px", cell: (e) => <Badge tone={tone(e.kind)}>{GROUPS.find((g) => g.id === groupOf(e.kind))?.label}</Badge> },
  { id: "title", header: "Event", width: "minmax(200px,1.4fr)", cell: (e) => sanitizeText(e.title) },
  { id: "detail", header: "Detail", width: "minmax(200px,2fr)", mono: true, cell: (e) => <span className="text-muted">{sanitizeText(e.detail ?? "")}</span> },
];

export function TimelineView() {
  const version = useEventsStore((s) => s.version);
  const { groups, text, flowId, window: userWindow, selectedEventId, toggleGroup, setText, setFlow, setWindow, selectEvent, resetFilters } = useTimelineStore();
  const capturing = useCaptureStore((s) => s.state === "capturing");
  const filterAst = useUiStore((s) => s.filterAst);

  // Time order: events from different stages can arrive slightly out of order.
  const events = useMemo(() => {
    const filtered = filterItems(eventBuffer.rows.filter((e) => matchesFilter(e, { groups, text, flowId })), filterAst, new EventSubject());
    return filtered.sort((a, b) => a.ts - b.ts || a.id - b.id);
  }, [version, groups, text, flowId, filterAst]); // eslint-disable-line react-hooks/exhaustive-deps

  const bounds: Range = useMemo(() => {
    if (events.length === 0) return { start: 0, end: 1_000_000 };
    const pad = Math.max(1_000, (events[events.length - 1].ts - events[0].ts) * 0.02);
    return { start: events[0].ts - pad, end: events[events.length - 1].ts + pad };
  }, [events]);

  const autoView: Range = useMemo(() => (capturing && bounds.end - bounds.start > AUTO_FOLLOW_SPAN ? { start: bounds.end - AUTO_FOLLOW_SPAN, end: bounds.end } : bounds), [capturing, bounds]);
  const view = userWindow ?? autoView;

  const visible = useMemo(() => {
    if (!userWindow) return events;
    const from = lowerBound(events, userWindow.start);
    const to = lowerBound(events, userWindow.end + 1);
    return events.slice(from, to);
  }, [events, userWindow]);

  const filtersActive = text !== "" || flowId !== null || groups.size !== ALL_GROUPS.length;

  return (
    <div className="flex h-full min-h-0 flex-col">
      <div className="flex shrink-0 flex-wrap items-center gap-2 border-b border-line px-3 py-2">
        <div role="group" aria-label="Event types" className="flex gap-1">
          {GROUPS.map((g) => (
            <button
              key={g.id}
              type="button"
              aria-pressed={groups.has(g.id)}
              onClick={() => toggleGroup(g.id)}
              className={cn("rounded border px-2 py-1 text-xs transition-colors duration-150", groups.has(g.id) ? "border-primary-muted bg-primary-muted/30 text-fg" : "border-line text-faint hover:bg-hover")}
            >
              {g.label}
            </button>
          ))}
        </div>
        <Input mono className="w-64" placeholder="Filter host or domain…" aria-label="Filter events by host or domain" value={text} onChange={(e) => setText(e.target.value)} />
        {flowId !== null && (
          <span className="flex items-center gap-1 rounded border border-primary-muted bg-primary-muted/20 py-0.5 pl-2 pr-0.5 font-mono text-xs">
            Flow #{flowId}
            <IconButton label="Clear flow filter" className="h-5 w-5" onClick={() => setFlow(null)}>
              <X size={12} />
            </IconButton>
          </span>
        )}
        <div className="flex-1" />
        <span className="font-mono text-xs text-muted">{visible.length.toLocaleString("en-US")} events</span>
        <Button size="sm" variant="ghost" icon={<Maximize2 size={13} />} disabled={!userWindow} onClick={() => setWindow(null)}>
          {capturing ? "Follow" : "Fit"}
        </Button>
        {filtersActive && (
          <Button size="sm" variant="ghost" onClick={resetFilters}>
            Reset
          </Button>
        )}
      </div>
      <div className="shrink-0 border-b border-line">
        <TimelineChart events={events} view={view} bounds={bounds} selectedId={selectedEventId} groups={groups} onView={setWindow} onSelect={selectEvent} />
      </div>
      <p className="shrink-0 px-3 py-1 text-[11px] text-faint">Scroll to zoom · drag to pan · double-click to fit</p>
      <div className="min-h-0 flex-1 border-t border-line">
        <VirtualTable
          label="Events"
          columns={columns}
          rows={visible}
          rowKey={(e) => e.id}
          selectedKey={selectedEventId}
          onSelect={(e) => selectEvent(e.id)}
          empty={<EmptyState icon={<Activity size={26} />} title="No events" description={filtersActive ? "No events match the current filters." : "Events such as DNS lookups, connections and retransmissions appear here as traffic is captured."} />}
        />
      </div>
    </div>
  );
}
