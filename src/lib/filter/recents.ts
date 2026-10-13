import type { Recents } from "./suggest";

const MAX = 20;

/** Collects distinct values, newest first, from a stream given oldest → newest. */
export function newestDistinct(values: Iterable<string | null | undefined>, max = MAX): string[] {
  const seen = new Set<string>();
  const out: string[] = [];
  const all = [...values];
  for (let i = all.length - 1; i >= 0 && out.length < max; i--) {
    const v = all[i];
    if (v && !seen.has(v)) {
      seen.add(v);
      out.push(v);
    }
  }
  return out;
}

export function buildRecents(input: { ipsOldestFirst: Iterable<string | null | undefined>; domainsOldestFirst: Iterable<string | null | undefined> }): Recents {
  return { ips: newestDistinct(input.ipsOldestFirst), domains: newestDistinct(input.domainsOldestFirst) };
}
