import type { DnsTransaction } from "@/types/ipc";

export interface DomainRow {
  domain: string;
  queries: number;
  failures: number;
  avgLatency: number | null;
  lastSeen: number;
  /** Addresses this domain was seen resolving to. A domain can have many, and an address many domains. */
  addresses: string[];
}

const ADDRESS_TYPES = new Set(["A", "AAAA"]);

/** Groups transactions by (case-insensitive) query name; most recently asked first. */
export function aggregateDomains(transactions: Iterable<DnsTransaction>): DomainRow[] {
  const acc = new Map<string, { row: DomainRow; latSum: number; latN: number; addrs: Set<string> }>();
  for (const t of transactions) {
    const key = t.queryName.toLowerCase();
    let e = acc.get(key);
    if (!e) {
      e = { row: { domain: key, queries: 0, failures: 0, avgLatency: null, lastSeen: 0, addresses: [] }, latSum: 0, latN: 0, addrs: new Set() };
      acc.set(key, e);
    }
    e.row.queries++;
    if (t.status === "failed" || t.status === "timeout") e.row.failures++;
    e.row.lastSeen = Math.max(e.row.lastSeen, t.queryAt ?? t.responseAt ?? 0);
    if (t.latency !== null) {
      e.latSum += t.latency;
      e.latN++;
    }
    for (const a of t.answers) if (ADDRESS_TYPES.has(a.recordType)) e.addrs.add(a.data);
  }
  return [...acc.values()]
    .map(({ row, latSum, latN, addrs }) => ({ ...row, avgLatency: latN ? Math.round(latSum / latN) : null, addresses: [...addrs].sort() }))
    .sort((a, b) => b.lastSeen - a.lastSeen || a.domain.localeCompare(b.domain));
}

export function answersText(t: DnsTransaction, max = 3): string {
  const shown = t.answers.filter((a) => a.recordType !== "CNAME").slice(0, max).map((a) => a.data);
  if (shown.length === 0) return t.status === "pending" ? "…" : "—";
  return shown.join(", ") + (t.answers.length > max ? ", …" : "");
}
