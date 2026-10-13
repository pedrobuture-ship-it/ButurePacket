import { create } from "zustand";
import type { EventGroup } from "@/features/timeline/model";

export interface ViewWindow {
  start: number;
  end: number;
}

interface TimelineStore {
  groups: Set<EventGroup>;
  text: string;
  flowId: number | null;
  /** null = automatic window (follow live traffic / fit everything). */
  window: ViewWindow | null;
  selectedEventId: number | null;
  toggleGroup: (g: EventGroup) => void;
  setText: (t: string) => void;
  setFlow: (id: number | null) => void;
  setWindow: (w: ViewWindow | null) => void;
  selectEvent: (id: number | null) => void;
  resetFilters: () => void;
}

export const ALL_GROUPS: EventGroup[] = ["dns", "tcp", "tls", "problems", "traffic"];

export const useTimelineStore = create<TimelineStore>((set) => ({
  groups: new Set(ALL_GROUPS),
  text: "",
  flowId: null,
  window: null,
  selectedEventId: null,
  toggleGroup: (g) =>
    set((s) => {
      const next = new Set(s.groups);
      if (!next.delete(g)) next.add(g);
      return { groups: next };
    }),
  setText: (text) => set({ text }),
  setFlow: (flowId) => set({ flowId }),
  setWindow: (window) => set({ window }),
  selectEvent: (selectedEventId) => set({ selectedEventId }),
  resetFilters: () => set({ groups: new Set(ALL_GROUPS), text: "", flowId: null, window: null }),
}));
