import { create } from "zustand";
import type { FlowView } from "@/types/ipc";

/**
 * Flows are upserted in place into a Map (the backend only sends changed flows).
 * `version` is bumped at most a few times per second so views re-sort cheaply.
 */
export const flowBuffer = {
  byId: new Map<number, FlowView>(),
};

interface FlowsStore {
  version: number;
  selectedId: number | null;
  upsert: (flows: FlowView[]) => void;
  clear: () => void;
  select: (id: number | null) => void;
}

const PUBLISH_INTERVAL_MS = 250;
/** Flows kept in the UI; beyond it the least recently seen are dropped. */
export const MAX_FLOWS = 200_000;
const EVICT_FRACTION = 0.1;

/** Re-sorting and re-filtering a huge flow table costs real time, so refresh it less often. */
export function publishInterval(flowCount: number): number {
  return Math.min(2000, Math.max(PUBLISH_INTERVAL_MS, Math.round(flowCount / 100)));
}

function evictIfNeeded() {
  if (flowBuffer.byId.size <= MAX_FLOWS * (1 + EVICT_FRACTION)) return;
  const byAge = [...flowBuffer.byId.values()].sort((a, b) => a.lastSeenAt - b.lastSeenAt);
  for (const f of byAge.slice(0, flowBuffer.byId.size - MAX_FLOWS)) flowBuffer.byId.delete(f.id);
}
let timer: ReturnType<typeof setTimeout> | null = null;

export const useFlowsStore = create<FlowsStore>((set, get) => ({
  version: 0,
  selectedId: null,
  upsert: (flows) => {
    for (const f of flows) flowBuffer.byId.set(f.id, f);
    evictIfNeeded();
    if (timer) return;
    timer = setTimeout(() => {
      timer = null;
      set({ version: get().version + 1 });
    }, publishInterval(flowBuffer.byId.size));
  },
  clear: () => {
    flowBuffer.byId.clear();
    if (timer) clearTimeout(timer);
    timer = null;
    set({ version: get().version + 1, selectedId: null });
  },
  select: (selectedId) => set({ selectedId }),
}));
