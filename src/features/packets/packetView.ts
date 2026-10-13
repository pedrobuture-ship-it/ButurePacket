import { PacketSubject } from "@/lib/filter/adapters";
import { evaluate, type Node } from "@/lib/filter";
import { flowBuffer } from "@/stores/flows";
import { packetBuffer } from "@/stores/packets";
import type { PacketSummary } from "@/types/ipc";

/**
 * Filtered view over the packet buffer. Matching row positions are cached and extended
 * incrementally as new packets arrive, so a live filter costs O(new packets), not O(all).
 */
const subject = new PacketSubject((id) => flowBuffer.byId.get(id));
let cache: { ast: Node | null; processed: number; indices: number[] } = { ast: null, processed: 0, indices: [] };

/** Matching row positions for `ast`, or `null` when there is no filter (every row matches). */
export function filteredIndices(ast: Node | null, rowCount: number): number[] | null {
  if (ast === null) {
    cache = { ast: null, processed: 0, indices: [] };
    return null;
  }
  if (cache.ast !== ast || rowCount < cache.processed) cache = { ast, processed: 0, indices: [] };
  const rows = packetBuffer.rows;
  for (let i = cache.processed; i < rowCount; i++) {
    subject.item = rows[i];
    if (evaluate(ast, subject)) cache.indices.push(i);
  }
  cache.processed = rowCount;
  return cache.indices;
}

/** Forget cached matches (e.g. flows learned a domain, or the buffer was replaced). */
export function invalidatePacketView() {
  cache = { ast: null, processed: 0, indices: [] };
}

export interface PacketView {
  count: number;
  at: (i: number) => PacketSummary | undefined;
  /** Position of the packet with this id in the view, or -1. */
  positionOfId: (id: number) => number;
}

export function makePacketView(indices: number[] | null, rowCount: number): PacketView {
  if (indices === null) return { count: rowCount, at: (i) => packetBuffer.get(i), positionOfId: (id) => packetBuffer.indexOfId(id) };
  return {
    count: indices.length,
    at: (i) => (indices[i] === undefined ? undefined : packetBuffer.get(indices[i])),
    positionOfId: (id) => {
      const row = packetBuffer.indexOfId(id);
      if (row === -1) return -1;
      let lo = 0;
      let hi = indices.length - 1;
      while (lo <= hi) {
        const mid = (lo + hi) >> 1;
        if (indices[mid] === row) return mid;
        if (indices[mid] < row) lo = mid + 1;
        else hi = mid - 1;
      }
      return -1;
    },
  };
}
