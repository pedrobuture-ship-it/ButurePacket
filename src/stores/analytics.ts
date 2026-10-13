import { create } from "zustand";
import type { AnalyticsSnapshot } from "@/types/ipc";

export const EMPTY_ANALYTICS: AnalyticsSnapshot = {
  series: [],
  tcp: { packets: 0, retransmissions: 0, resets: 0, duplicateAcks: 0, zeroWindows: 0 },
  dns: { queries: 0, responses: 0, failures: 0, uniqueDomains: 0, avgLatency: null, p95Latency: null, resolvers: [] },
  rankings: { hosts: [], domains: [], protocols: [], ports: [], talkers: [] },
  problems: [],
};

interface AnalyticsStore {
  snapshot: AnalyticsSnapshot;
  set: (s: AnalyticsSnapshot) => void;
  reset: () => void;
}

export const useAnalyticsStore = create<AnalyticsStore>((set) => ({
  snapshot: EMPTY_ANALYTICS,
  set: (snapshot) => set({ snapshot }),
  reset: () => set({ snapshot: EMPTY_ANALYTICS }),
}));
