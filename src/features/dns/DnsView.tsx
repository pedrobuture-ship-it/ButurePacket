import { useMemo, useState } from "react";
import { Badge, EmptyState, Input, Metric, Tabs, VirtualTable, type BadgeTone, type VColumn } from "@/components/ui";
import { formatCount, formatLatency, formatTimestamp } from "@/lib/format";
import { dnsBuffer, useDnsStore } from "@/stores/dns";
import type { DnsStatus, DnsTransaction, ResolverStat } from "@/types/ipc";
import { type DomainRow, aggregateDomains, answersText } from "./aggregate";

type Tab = "queries" | "domains" | "resolvers";
const TABS: { id: Tab; label: string }[] = [
  { id: "queries", label: "Queries" },
  { id: "domains", label: "Domains" },
  { id: "resolvers", label: "Resolvers" },
];

const statusTone: Record<DnsStatus, BadgeTone> = { ok: "success", failed: "danger", timeout: "warning", pending: "neutral" };

const queryColumns: VColumn<DnsTransaction>[] = [
  { id: "time", header: "Time", width: "104px", mono: true, cell: (t) => ((t.queryAt ?? t.responseAt) ? formatTimestamp((t.queryAt ?? t.responseAt)!) : "—") },
  { id: "client", header: "Client", width: "130px", mono: true, cell: (t) => t.client },
  { id: "resolver", header: "Resolver", width: "130px", mono: true, cell: (t) => t.resolver },
  { id: "name", header: "Query", width: "minmax(180px,2fr)", mono: true, cell: (t) => t.queryName },
  { id: "type", header: "Type", width: "64px", mono: true, cell: (t) => t.queryType },
  { id: "latency", header: "Latency", width: "84px", mono: true, cell: (t) => formatLatency(t.latency) },
  { id: "status", header: "Status", width: "104px", cell: (t) => <Badge tone={statusTone[t.status]}>{t.responseCode && t.status === "failed" ? t.responseCode : t.status}</Badge> },
  { id: "answers", header: "Answers", width: "minmax(160px,2fr)", mono: true, cell: (t) => answersText(t) },
];

const domainColumns: VColumn<DomainRow>[] = [
  { id: "domain", header: "Domain", width: "minmax(180px,2fr)", mono: true, cell: (d) => d.domain },
  { id: "queries", header: "Queries", width: "80px", mono: true, cell: (d) => formatCount(d.queries) },
  { id: "failures", header: "Failures", width: "80px", mono: true, cell: (d) => (d.failures ? <span className="text-danger">{d.failures}</span> : 0) },
  { id: "latency", header: "Avg latency", width: "100px", mono: true, cell: (d) => formatLatency(d.avgLatency) },
  { id: "addresses", header: "Seen resolving to", width: "minmax(160px,2fr)", mono: true, cell: (d) => (d.addresses.length ? d.addresses.slice(0, 3).join(", ") + (d.addresses.length > 3 ? ", …" : "") : "—") },
];

const resolverColumns: VColumn<ResolverStat>[] = [
  { id: "ip", header: "Resolver", width: "minmax(160px,2fr)", mono: true, cell: (r) => r.ip },
  { id: "queries", header: "Queries", width: "100px", mono: true, cell: (r) => formatCount(r.queries) },
  { id: "failures", header: "Failures", width: "100px", mono: true, cell: (r) => (r.failures ? <span className="text-danger">{r.failures}</span> : 0) },
  { id: "latency", header: "Avg latency", width: "120px", mono: true, cell: (r) => formatLatency(r.avgLatency) },
];

export function DnsView() {
  const version = useDnsStore((s) => s.version);
  const stats = useDnsStore((s) => s.stats);
  const [tab, setTab] = useState<Tab>("queries");
  const [search, setSearch] = useState("");

  // Newest first; the filter box matches the query name.
  const transactions = useMemo(() => {
    const needle = search.trim().toLowerCase();
    const all = [...dnsBuffer.byId.values()].sort((a, b) => b.id - a.id);
    return needle ? all.filter((t) => t.queryName.toLowerCase().includes(needle)) : all;
  }, [version, search]); // eslint-disable-line react-hooks/exhaustive-deps
  const domains = useMemo(() => aggregateDomains(transactions), [transactions]);

  const empty = <EmptyState title="No DNS traffic" description="DNS queries and responses on port 53 appear here as they are captured." />;
  return (
    <div className="flex h-full min-h-0 flex-col">
      <div className="flex shrink-0 items-center gap-8 border-b border-line px-4 py-3">
        <Metric label="Queries" value={formatCount(stats.queries)} />
        <Metric label="Responses" value={formatCount(stats.responses)} />
        <Metric label="Failures" value={<span className={stats.failures ? "text-danger" : undefined}>{formatCount(stats.failures)}</span>} />
        <Metric label="Domains" value={formatCount(stats.uniqueDomains)} />
        <Metric label="Avg latency" value={formatLatency(stats.avgLatency)} />
        <Metric label="p95 latency" value={formatLatency(stats.p95Latency)} />
        <div className="flex-1" />
        <Input mono className="w-64" placeholder="Search domain…" aria-label="Search domain" value={search} onChange={(e) => setSearch(e.target.value)} />
      </div>
      <Tabs tabs={TABS} value={tab} onChange={setTab} className="shrink-0 px-2" />
      <div className="min-h-0 flex-1">
        {tab === "queries" && <VirtualTable label="DNS queries" columns={queryColumns} rows={transactions} rowKey={(t) => t.id} empty={empty} />}
        {tab === "domains" && <VirtualTable label="DNS domains" columns={domainColumns} rows={domains} rowKey={(d) => d.domain} empty={empty} />}
        {tab === "resolvers" && <VirtualTable label="DNS resolvers" columns={resolverColumns} rows={stats.resolvers} rowKey={(r) => r.ip} empty={empty} />}
      </div>
    </div>
  );
}
