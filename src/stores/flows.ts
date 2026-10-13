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
let timer: ReturnType<typeof setTimeout> | null = null;

export const useFlowsStore = create<FlowsStore>((set, get) => ({
  version: 0,
  selectedId: null,
  upsert: (flows) => {
    for (const f of flows) flowBuffer.byId.set(f.id, f);
    if (timer) return;
    timer = setTimeout(() => {
      timer = null;
      set({ version: get().version + 1 });
    }, PUBLISH_INTERVAL_MS);
  },
  clear: () => {
    flowBuffer.byId.clear();
    if (timer) clearTimeout(timer);
    timer = null;
    set({ version: get().version + 1, selectedId: null });
  },
  select: (selectedId) => set({ selectedId }),
}));
