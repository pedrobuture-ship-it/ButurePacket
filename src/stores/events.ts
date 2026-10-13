import { create } from "zustand";
import type { TimelineEvent } from "@/types/ipc";

/** Events arrive roughly in time order; kept in a mutable array with a throttled version counter. */
export const eventBuffer = {
  rows: [] as TimelineEvent[],
};

const MAX_EVENTS = 300_000;
const PUBLISH_INTERVAL_MS = 250;
let timer: ReturnType<typeof setTimeout> | null = null;

interface EventsStore {
  version: number;
  append: (events: TimelineEvent[]) => void;
  clear: () => void;
}

export const useEventsStore = create<EventsStore>((set, get) => ({
  version: 0,
  append: (events) => {
    for (const e of events) eventBuffer.rows.push(e);
    if (eventBuffer.rows.length > MAX_EVENTS) eventBuffer.rows.splice(0, eventBuffer.rows.length - MAX_EVENTS);
    if (timer) return;
    timer = setTimeout(() => {
      timer = null;
      set({ version: get().version + 1 });
    }, PUBLISH_INTERVAL_MS);
  },
  clear: () => {
    eventBuffer.rows = [];
    if (timer) clearTimeout(timer);
    timer = null;
    set({ version: get().version + 1 });
  },
}));
