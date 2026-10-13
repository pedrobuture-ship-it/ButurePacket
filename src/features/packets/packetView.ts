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
let cache: { ast: Node | null; processed: number; indices: number[]; generation: number } = { ast: null, processed: 0, indices: [], generation: 0 };

export interface FilterProgress {
  /** Matching row positions so far, or `null` when there is no filter (every row matches). */
  indices: number[] | null;
  /** All rows have been examined. */
  done: boolean;
  /** Rows examined so far (for a progress indicator). */
  processed: number;
}

/**
 * Advances the filter over new rows, stopping after `budgetMs` so a huge buffer never blocks the
 * UI thread: callers show partial results and call again until `done`.
 */
export function filterProgress(ast: Node | null, rowCount: number, budgetMs = Infinity): FilterProgress {
  if (ast === null) {
    cache = { ast: null, processed: 0, indices: [], generation: packetBuffer.generation };
    return { indices: null, done: true, processed: rowCount };
  }
  if (cache.ast !== ast || rowCount < cache.processed || cache.generation !== packetBuffer.generation) cache = { ast, processed: 0, indices: [], generation: packetBuffer.generation };
  const rows = packetBuffer.rows;
  const deadline = performance.now() + budgetMs;
  let i = cache.processed;
  while (i < rowCount) {
    // Check the clock every 2,048 rows: cheap enough, fine enough.
    const stop = Math.min(rowCount, i + 2048);
    for (; i < stop; i++) {
      subject.item = rows[i];
      if (evaluate(ast, subject)) cache.indices.push(i);
    }
    if (performance.now() >= deadline) break;
  }
  cache.processed = i;
  return { indices: cache.indices, done: i >= rowCount, processed: i };
}

/** Matching row positions for `ast`, or `null` when there is no filter (every row matches). */
export function filteredIndices(ast: Node | null, rowCount: number): number[] | null {
  return filterProgress(ast, rowCount).indices;
}

/** Forget cached matches (e.g. flows learned a domain, or the buffer was replaced). */
export function invalidatePacketView() {
  cache = { ast: null, processed: 0, indices: [], generation: packetBuffer.generation };
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
