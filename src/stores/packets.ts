import { create } from "zustand";
import { Interner, ListInterner } from "@/lib/intern";
import { useNoticeStore } from "@/stores/notices";
import type { PacketSummary } from "@/types/ipc";

const strings = new Interner();
const flagLists = new ListInterner();
const NO_ISSUES: string[] = [];

/** Shares repeated strings and arrays so a large capture stays small in memory. */
function compact(p: PacketSummary): PacketSummary {
  p.sourceMac = strings.intern(p.sourceMac);
  p.destinationMac = strings.intern(p.destinationMac);
  p.sourceIp = strings.intern(p.sourceIp);
  p.destinationIp = strings.intern(p.destinationIp);
  p.networkProtocol = strings.intern(p.networkProtocol);
  p.transportProtocol = strings.intern(p.transportProtocol);
  p.applicationProtocol = strings.intern(p.applicationProtocol);
  p.tcpFlags = flagLists.intern(p.tcpFlags) as string[] | null;
  if (p.issues.length === 0) p.issues = NO_ISSUES;
  return p;
}

/**
 * Packet rows live in a plain mutable array: copying an immutable array on every
 * 50ms batch would be O(n) at hundreds of thousands of rows. The zustand store
 * only carries a cheap change counter that views subscribe to.
 */
/** Rows kept in the UI. Older ones are dropped (the backend and database still have them). */
export const MAX_ROWS = 1_000_000;
const TRIM_CHUNK = 100_000;

export const packetBuffer = {
  rows: [] as PacketSummary[],
  /** Bumps whenever rows are removed from the front, invalidating cached row positions. */
  generation: 0,

  get(index: number): PacketSummary | undefined {
    return this.rows[index];
  },

  /** Rows are appended in increasing id order, so binary search works. */
  indexOfId(id: number): number {
    let lo = 0;
    let hi = this.rows.length - 1;
    while (lo <= hi) {
      const mid = (lo + hi) >> 1;
      const v = this.rows[mid].id;
      if (v === id) return mid;
      if (v < id) lo = mid + 1;
      else hi = mid - 1;
    }
    return -1;
  },
};

interface PacketsStore {
  /** Number of rows in `packetBuffer`; changes trigger re-render of subscribers. */
  count: number;
  selectedId: number | null;
  inspectorOpen: boolean;
  append: (batch: PacketSummary[]) => void;
  clear: () => void;
  select: (id: number | null) => void;
  setInspectorOpen: (open: boolean) => void;
}

let pending = false;
let warnedAboutCap = false;

export const usePacketsStore = create<PacketsStore>((set) => ({
  count: 0,
  selectedId: null,
  inspectorOpen: true,
  append: (batch) => {
    for (const p of batch) packetBuffer.rows.push(compact(p));
    if (packetBuffer.rows.length > MAX_ROWS + TRIM_CHUNK) {
      packetBuffer.rows.splice(0, packetBuffer.rows.length - MAX_ROWS);
      packetBuffer.generation++;
      if (!warnedAboutCap) {
        warnedAboutCap = true;
        useNoticeStore.getState().push("warning", `The packet list keeps the latest ${MAX_ROWS.toLocaleString("en-US")} packets; older rows were removed from the list.`, "Use filters to narrow things down, or save the capture. Flows and analytics are not affected.", "Memory limit");
      }
    }
    // Coalesce bursts of batches into one render per frame.
    if (pending) return;
    pending = true;
    const flush = () => {
      pending = false;
      set({ count: packetBuffer.rows.length });
    };
    if (typeof requestAnimationFrame === "function") requestAnimationFrame(flush);
    else queueMicrotask(flush);
  },
  clear: () => {
    warnedAboutCap = false;
    packetBuffer.rows = [];
    strings.clear();
    flagLists.clear();
    set({ count: 0, selectedId: null });
  },
  select: (selectedId) => set({ selectedId }),
  setInspectorOpen: (inspectorOpen) => set({ inspectorOpen }),
}));
