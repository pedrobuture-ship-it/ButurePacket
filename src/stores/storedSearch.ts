import { create } from "zustand";
import { api } from "@/lib/api";
import { describeError, type AppError } from "@/lib/errors";
import type { PacketSummary, StoredPacketQuery } from "@/types/ipc";

export const PAGE_SIZE = 5000;

interface StoredSearch {
  /** The packet list shows results from the stored capture instead of the in-memory rows. */
  enabled: boolean;
  loading: boolean;
  rows: PacketSummary[];
  /** Matches in the whole stored capture. */
  total: number;
  error: AppError | null;
  /** Why the current filter can't be searched there, if it can't. */
  unsupported: string | null;
  setEnabled: (enabled: boolean) => void;
  setUnsupported: (reason: string | null) => void;
  /** Starts over with a new query (a newer call supersedes an older one still in flight). */
  load: (query: StoredPacketQuery) => Promise<void>;
  loadMore: (query: StoredPacketQuery) => Promise<void>;
  reset: () => void;
}

let generation = 0;

export const useStoredSearch = create<StoredSearch>((set, get) => ({
  enabled: false,
  loading: false,
  rows: [],
  total: 0,
  error: null,
  unsupported: null,
  setEnabled: (enabled) => set({ enabled, ...(enabled ? {} : { rows: [], total: 0, error: null, unsupported: null }) }),
  setUnsupported: (unsupported) => set({ unsupported, ...(unsupported ? { rows: [], total: 0, loading: false } : {}) }),
  load: async (query) => {
    const mine = ++generation;
    set({ loading: true, error: null, unsupported: null });
    try {
      const page = await api.queryStoredPackets({ ...query, limit: PAGE_SIZE });
      if (mine === generation) set({ rows: page.packets, total: page.total, loading: false });
    } catch (e) {
      if (mine === generation) set({ rows: [], total: 0, loading: false, error: describeError(e) });
    }
  },
  loadMore: async (query) => {
    const { rows, loading } = get();
    if (loading || rows.length === 0) return;
    const mine = ++generation;
    set({ loading: true });
    try {
      const page = await api.queryStoredPackets({ ...query, afterId: rows[rows.length - 1].id, limit: PAGE_SIZE });
      if (mine === generation) set({ rows: [...rows, ...page.packets], total: page.total, loading: false });
    } catch (e) {
      if (mine === generation) set({ loading: false, error: describeError(e) });
    }
  },
  reset: () => {
    generation++;
    set({ enabled: false, loading: false, rows: [], total: 0, error: null, unsupported: null });
  },
}));
