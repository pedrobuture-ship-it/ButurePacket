import { useEffect, useRef, useState } from "react";
import { formatClock, GROUPS, groupOf, KIND_COLOR, lowerBound, MIN_SPAN_MICROS, niceTicks, panRange, timeToX, xToTime, zoomRange, type EventGroup, type Range } from "./model";
import type { TimelineEvent } from "@/types/ipc";

const GUTTER = 76;
const AXIS_H = 24;
const LANE_H = 30;
const COLORS = { bg: "#07100d", grid: "rgba(36,80,62,0.35)", lane: "rgba(16,32,25,0.55)", text: "#70877a", axis: "#4d6257", select: "#ffffff" };
export const CHART_HEIGHT = AXIS_H + GROUPS.length * LANE_H + 6;

interface Props {
  /** Filtered events sorted by time. */
  events: readonly TimelineEvent[];
  view: Range;
  bounds: Range;
  selectedId: number | null;
  onView: (r: Range) => void;
  onSelect: (id: number | null) => void;
  /** Enabled lanes; others are drawn dimmed. */
  groups: ReadonlySet<EventGroup>;
}

function laneY(group: EventGroup): number {
  return AXIS_H + GROUPS.findIndex((g) => g.id === group) * LANE_H;
}

export function TimelineChart({ events, view, bounds, selectedId, onView, onSelect, groups }: Props) {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const wrapRef = useRef<HTMLDivElement>(null);
  const [width, setWidth] = useState(800);
  const [hover, setHover] = useState<{ event: TimelineEvent; x: number; y: number } | null>(null);
  const drag = useRef<{ x: number; view: Range; moved: boolean } | null>(null);
  const live = useRef({ view, bounds, onView });
  useEffect(() => {
    live.current = { view, bounds, onView };
  }, [view, bounds, onView]);

  useEffect(() => {
    const el = wrapRef.current;
    if (!el) return;
    const ro = new ResizeObserver(() => setWidth(Math.max(200, el.clientWidth)));
    ro.observe(el);
    setWidth(Math.max(200, el.clientWidth));
    return () => ro.disconnect();
  }, []);

  // Wheel zoom needs a non-passive listener to stop the page from scrolling.
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const onWheel = (e: WheelEvent) => {
      e.preventDefault();
      const rect = canvas.getBoundingClientRect();
      const plotW = rect.width - GUTTER;
      const x = Math.min(Math.max(e.clientX - rect.left - GUTTER, 0), plotW);
      const { view: v, bounds: b, onView: set } = live.current;
      set(zoomRange(v, xToTime(x, v, plotW), e.deltaY < 0 ? 0.8 : 1.25, b));
    };
    canvas.addEventListener("wheel", onWheel, { passive: false });
    return () => canvas.removeEventListener("wheel", onWheel);
  }, []);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const dpr = window.devicePixelRatio || 1;
    canvas.width = Math.round(width * dpr);
    canvas.height = Math.round(CHART_HEIGHT * dpr);
    const ctx = canvas.getContext("2d");
    if (!ctx) return;
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    const plotW = width - GUTTER;
    ctx.fillStyle = COLORS.bg;
    ctx.fillRect(0, 0, width, CHART_HEIGHT);

    // lanes
    ctx.font = "10px 'JetBrains Mono', monospace";
    ctx.textBaseline = "middle";
    GROUPS.forEach((g, i) => {
      const y = AXIS_H + i * LANE_H;
      ctx.fillStyle = i % 2 ? "rgba(0,0,0,0)" : COLORS.lane;
      ctx.fillRect(GUTTER, y, plotW, LANE_H);
      ctx.fillStyle = groups.has(g.id) ? COLORS.text : COLORS.axis;
      ctx.fillText(g.label, 10, y + LANE_H / 2);
    });

    // axis + vertical grid
    const span = view.end - view.start;
    ctx.textBaseline = "alphabetic";
    for (const t of niceTicks(view, Math.max(3, Math.floor(plotW / 110)))) {
      const x = GUTTER + timeToX(t, view, plotW);
      ctx.strokeStyle = COLORS.grid;
      ctx.beginPath();
      ctx.moveTo(x + 0.5, AXIS_H - 4);
      ctx.lineTo(x + 0.5, CHART_HEIGHT);
      ctx.stroke();
      ctx.fillStyle = COLORS.text;
      ctx.fillText(formatClock(t, span < 20_000_000), x + 4, AXIS_H - 8);
    }

    // markers (only the slice inside the view)
    const first = Math.max(0, lowerBound(events, view.start) - 1);
    for (let i = first; i < events.length; i++) {
      const e = events[i];
      if (e.ts > view.end) break;
      const g = groupOf(e.kind);
      const x = GUTTER + timeToX(e.ts, view, plotW);
      const y = laneY(g);
      ctx.fillStyle = KIND_COLOR[e.kind];
      ctx.globalAlpha = groups.has(g) ? 1 : 0.25;
      if (e.id === selectedId) {
        ctx.strokeStyle = COLORS.select;
        ctx.strokeRect(x - 3.5, y + 5.5, 7, LANE_H - 11);
      }
      ctx.fillRect(x - 1.5, y + 7, 3, LANE_H - 14);
      ctx.globalAlpha = 1;
    }
  }, [events, view, width, selectedId, groups]);

  const hit = (clientX: number, clientY: number): TimelineEvent | null => {
    const rect = canvasRef.current?.getBoundingClientRect();
    if (!rect) return null;
    const plotW = rect.width - GUTTER;
    const x = clientX - rect.left - GUTTER;
    const y = clientY - rect.top;
    if (x < 0 || x > plotW || y < AXIS_H) return null;
    const lane = GROUPS[Math.floor((y - AXIS_H) / LANE_H)]?.id;
    if (!lane) return null;
    const t = xToTime(x, view, plotW);
    const tol = ((view.end - view.start) / plotW) * 5;
    let best: TimelineEvent | null = null;
    for (let i = Math.max(0, lowerBound(events, t - tol) - 1); i < events.length && events[i].ts <= t + tol; i++) {
      const e = events[i];
      if (groupOf(e.kind) === lane && (!best || Math.abs(e.ts - t) < Math.abs(best.ts - t))) best = e;
    }
    return best;
  };

  return (
    <div ref={wrapRef} className="relative w-full" style={{ height: CHART_HEIGHT }}>
      <canvas
        ref={canvasRef}
        role="img"
        aria-label="Event timeline"
        style={{ width: "100%", height: CHART_HEIGHT, cursor: drag.current ? "grabbing" : "crosshair", touchAction: "none" }}
        onPointerDown={(e) => {
          e.currentTarget.setPointerCapture(e.pointerId);
          drag.current = { x: e.clientX, view, moved: false };
        }}
        onPointerMove={(e) => {
          const d = drag.current;
          if (d) {
            const plotW = e.currentTarget.getBoundingClientRect().width - GUTTER;
            const dt = -((e.clientX - d.x) / plotW) * (d.view.end - d.view.start);
            if (Math.abs(e.clientX - d.x) > 3) d.moved = true;
            if (d.moved) onView(panRange(d.view, dt, bounds));
            return;
          }
          const found = hit(e.clientX, e.clientY);
          const rect = e.currentTarget.getBoundingClientRect();
          setHover(found ? { event: found, x: e.clientX - rect.left, y: e.clientY - rect.top } : null);
        }}
        onPointerUp={(e) => {
          const d = drag.current;
          drag.current = null;
          if (d && !d.moved) onSelect(hit(e.clientX, e.clientY)?.id ?? null);
        }}
        onPointerLeave={() => setHover(null)}
        onDoubleClick={() => onView({ start: bounds.start, end: Math.max(bounds.end, bounds.start + MIN_SPAN_MICROS) })}
      />
      {hover && (
        <div className="pointer-events-none absolute z-10 max-w-sm rounded border border-line-strong bg-raised px-2 py-1 text-[11px] shadow-lg" style={{ left: Math.min(hover.x + 12, width - 260), top: hover.y + 14 }}>
          <div className="font-mono text-muted">{formatClock(hover.event.ts, true)}</div>
          <div className="text-fg">{hover.event.title}</div>
          {hover.event.detail && <div className="font-mono text-muted">{hover.event.detail}</div>}
        </div>
      )}
    </div>
  );
}
