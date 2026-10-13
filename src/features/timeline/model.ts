import { formatClock } from "@/lib/format";
import type { EventKind, TimelineEvent } from "@/types/ipc";

export { formatClock };

export type EventGroup = "dns" | "tcp" | "tls" | "problems" | "traffic";

export const GROUPS: { id: EventGroup; label: string }[] = [
  { id: "dns", label: "DNS" },
  { id: "tcp", label: "TCP" },
  { id: "tls", label: "TLS" },
  { id: "problems", label: "Problems" },
  { id: "traffic", label: "Traffic" },
];

const GROUP_OF: Record<EventKind, EventGroup> = {
  dnsQuery: "dns",
  dnsResponse: "dns",
  dnsFailure: "dns",
  flowStarted: "tcp",
  tcpConnect: "tcp",
  flowEnded: "tcp",
  tlsHandshake: "tls",
  retransmission: "problems",
  reset: "problems",
  latencySpike: "problems",
  trafficBurst: "traffic",
};

export const groupOf = (kind: EventKind): EventGroup => GROUP_OF[kind];

/** Marker colour per kind (hex, matching the design palette). */
export const KIND_COLOR: Record<EventKind, string> = {
  dnsQuery: "#5aa9e0",
  dnsResponse: "#7cc4f0",
  dnsFailure: "#e2615a",
  flowStarted: "#58e38c",
  tcpConnect: "#58e38c",
  flowEnded: "#2e8f58",
  tlsHandshake: "#a78bfa",
  retransmission: "#d9a548",
  reset: "#e2615a",
  latencySpike: "#d9a548",
  trafficBurst: "#d9a548",
};

export interface EventFilter {
  groups: ReadonlySet<EventGroup>;
  /** Case-insensitive substring matched against host, domain and title. */
  text: string;
  flowId: number | null;
}

export function matchesFilter(e: TimelineEvent, f: EventFilter): boolean {
  if (!f.groups.has(groupOf(e.kind))) return false;
  if (f.flowId !== null && e.flowId !== f.flowId) return false;
  const needle = f.text.trim().toLowerCase();
  if (!needle) return true;
  return [e.host, e.domain, e.title, e.detail].some((v) => v?.toLowerCase().includes(needle));
}

export interface Range {
  start: number;
  end: number;
}

export const MIN_SPAN_MICROS = 1_000; // 1 ms

/** Maps a timestamp onto [0, width]. */
export function timeToX(t: number, view: Range, width: number): number {
  const span = view.end - view.start;
  return span <= 0 ? 0 : ((t - view.start) / span) * width;
}

export function xToTime(x: number, view: Range, width: number): number {
  return view.start + (width <= 0 ? 0 : (x / width) * (view.end - view.start));
}

/** Zooms around `anchor` (a timestamp) by `factor` (<1 zooms in), never outside `bounds`. */
export function zoomRange(view: Range, anchor: number, factor: number, bounds: Range): Range {
  const maxSpan = Math.max(bounds.end - bounds.start, MIN_SPAN_MICROS);
  const span = Math.min(maxSpan, Math.max(MIN_SPAN_MICROS, (view.end - view.start) * factor));
  const ratio = view.end === view.start ? 0.5 : (anchor - view.start) / (view.end - view.start);
  return clampRange({ start: anchor - ratio * span, end: anchor - ratio * span + span }, bounds);
}

export function panRange(view: Range, deltaMicros: number, bounds: Range): Range {
  return clampRange({ start: view.start + deltaMicros, end: view.end + deltaMicros }, bounds);
}

/** Slides a range back inside `bounds` without changing its span. */
export function clampRange(r: Range, bounds: Range): Range {
  const span = r.end - r.start;
  if (span >= bounds.end - bounds.start) return { start: bounds.start, end: bounds.end };
  const start = Math.min(Math.max(r.start, bounds.start), bounds.end - span);
  return { start, end: start + span };
}

const STEPS_MICROS = [1e3, 2e3, 5e3, 1e4, 2e4, 5e4, 1e5, 2e5, 5e5, 1e6, 2e6, 5e6, 1e7, 2e7, 3e7, 6e7, 12e7, 3e8, 6e8, 18e8, 36e8];

/** Round tick positions covering `view`, roughly `target` of them. */
export function niceTicks(view: Range, target = 8): number[] {
  const span = view.end - view.start;
  if (span <= 0) return [];
  const raw = span / target;
  const step = STEPS_MICROS.find((s) => s >= raw) ?? STEPS_MICROS[STEPS_MICROS.length - 1];
  const out: number[] = [];
  for (let t = Math.ceil(view.start / step) * step; t <= view.end; t += step) out.push(t);
  return out;
}

/** Index of the first event with ts >= t (events sorted by ts). */
export function lowerBound(events: readonly TimelineEvent[], t: number): number {
  let lo = 0;
  let hi = events.length;
  while (lo < hi) {
    const mid = (lo + hi) >> 1;
    if (events[mid].ts < t) lo = mid + 1;
    else hi = mid;
  }
  return lo;
}
