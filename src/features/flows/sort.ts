import type { FlowView } from "@/types/ipc";

export type FlowSort = "traffic" | "duration" | "latency" | "packets" | "newest" | "oldest";

export const FLOW_SORTS: { value: FlowSort; label: string }[] = [
  { value: "traffic", label: "Traffic" },
  { value: "duration", label: "Duration" },
  { value: "latency", label: "Latency" },
  { value: "packets", label: "Packets" },
  { value: "newest", label: "Newest" },
  { value: "oldest", label: "Oldest" },
];

const comparators: Record<FlowSort, (a: FlowView, b: FlowView) => number> = {
  traffic: (a, b) => b.totalBytes - a.totalBytes,
  duration: (a, b) => b.duration - a.duration,
  // Flows without a measurable latency sink to the bottom.
  latency: (a, b) => (b.latency ?? -1) - (a.latency ?? -1),
  packets: (a, b) => b.totalPackets - a.totalPackets,
  newest: (a, b) => b.startedAt - a.startedAt,
  oldest: (a, b) => a.startedAt - b.startedAt,
};

/** Returns a new, sorted array; ties are broken by id so the order is stable between refreshes. */
export function sortFlows(flows: FlowView[], sort: FlowSort): FlowView[] {
  const cmp = comparators[sort];
  return [...flows].sort((a, b) => cmp(a, b) || a.id - b.id);
}
