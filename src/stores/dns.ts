import { create } from "zustand";
import type { DnsPayload, DnsStats, DnsTransaction } from "@/types/ipc";

/** Mutable transaction table; the store carries only a throttled version counter. */
export const dnsBuffer = {
  byId: new Map<number, DnsTransaction>(),
};

export const EMPTY_DNS_STATS: DnsStats = { queries: 0, responses: 0, failures: 0, uniqueDomains: 0, avgLatency: null, p95Latency: null, resolvers: [] };

interface DnsStore {
  version: number;
  stats: DnsStats;
  apply: (payload: DnsPayload) => void;
  clear: () => void;
}

const PUBLISH_INTERVAL_MS = 250;
/** Transactions kept in the UI (the backend keeps the same number). */
export const MAX_TRANSACTIONS = 100_000;
let timer: ReturnType<typeof setTimeout> | null = null;

export const useDnsStore = create<DnsStore>((set, get) => ({
  version: 0,
  stats: EMPTY_DNS_STATS,
  apply: ({ transactions, stats }) => {
    for (const t of transactions) dnsBuffer.byId.set(t.id, t);
    // Maps iterate in insertion order, so the first keys are the oldest transactions.
    for (const id of dnsBuffer.byId.keys()) {
      if (dnsBuffer.byId.size <= MAX_TRANSACTIONS) break;
      dnsBuffer.byId.delete(id);
    }
    if (stats) set({ stats });
    if (timer) return;
    timer = setTimeout(() => {
      timer = null;
      set({ version: get().version + 1 });
    }, PUBLISH_INTERVAL_MS);
  },
  clear: () => {
    dnsBuffer.byId.clear();
    if (timer) clearTimeout(timer);
    timer = null;
    set({ version: get().version + 1, stats: EMPTY_DNS_STATS });
  },
}));
