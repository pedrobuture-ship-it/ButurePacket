import type { FlowView, RankEntry } from "@/types/ipc";

export interface Slice {
  key: string;
  bytes: number;
  fraction: number;
}

/** Turns a ranking into at most `max` slices, folding the rest into "Other". */
export function distribution(entries: readonly RankEntry[], max = 5): Slice[] {
  const total = entries.reduce((s, e) => s + e.bytes, 0);
  if (total <= 0) return [];
  const head = entries.slice(0, max).map((e) => ({ key: e.key, bytes: e.bytes, fraction: e.bytes / total }));
  const rest = entries.slice(max).reduce((s, e) => s + e.bytes, 0);
  return rest > 0 ? [...head, { key: "Other", bytes: rest, fraction: rest / total }] : head;
}

export function topConnections(flows: Iterable<FlowView>, n = 6): FlowView[] {
  return [...flows].sort((a, b) => b.totalBytes - a.totalBytes || a.id - b.id).slice(0, n);
}

/**
 * Which flow deserves a story on the overview: the most recently active one that has something
 * to tell (a name, TLS, or trouble), falling back to the most recent flow at all.
 */
export function pickStoryFlow(flows: Iterable<FlowView>): FlowView | null {
  let best: FlowView | null = null;
  let bestScore = -1;
  let latest: FlowView | null = null;
  for (const f of flows) {
    if (!latest || f.lastSeenAt > latest.lastSeenAt) latest = f;
    const interesting = (f.tls ? 1 : 0) + (f.domains.length ? 1 : 0) + (f.retransmissions + f.resets > 0 ? 1 : 0);
    if (interesting === 0 || f.totalBytes < 1024) continue;
    const score = f.lastSeenAt + interesting * 1_000_000;
    if (score > bestScore) {
      best = f;
      bestScore = score;
    }
  }
  return best ?? latest;
}

export function uniqueDomains(flows: Iterable<FlowView>): number {
  const set = new Set<string>();
  for (const f of flows) {
    if (f.tls?.sni) set.add(f.tls.sni.toLowerCase());
    for (const d of f.domains) set.add(d.toLowerCase());
  }
  return set.size;
}
