import type { ReactNode } from "react";
import { AlertTriangle, CheckCircle2 } from "lucide-react";
import { Badge, Panel, Sparkline, type BadgeTone } from "@/components/ui";
import { cn } from "@/lib/cn";
import { formatBytes, formatCount, formatLatency, formatPercent, formatRate } from "@/lib/format";
import { useAnalyticsStore } from "@/stores/analytics";
import type { ProblemLabel, RankEntry } from "@/types/ipc";
import { useCaptureStore } from "@/stores/capture";
import { type SeriesKey, barFractions, currentRate, latest, seriesValues, summarizeSeries, tcpHealth } from "./derive";
import { ModeBadge } from "@/components/ModeBadge";

function Card({ label, value, hint, values, tone = "text-primary" }: { label: string; value: ReactNode; hint?: string; values: number[]; tone?: string }) {
  return (
    <div className="flex flex-col gap-1 rounded border border-line bg-surface px-4 py-3">
      <span className="text-[11px] text-muted">{label}</span>
      <div className="flex items-end justify-between gap-3">
        <div className="flex flex-col gap-1">
          <span className="whitespace-nowrap font-mono text-2xl leading-none text-fg">{value}</span>
          {hint && <span className="font-mono text-[10px] text-faint">{hint}</span>}
        </div>
        <Sparkline values={values} width={120} height={36} className={tone} label={`${label} over the last minute`} />
      </div>
    </div>
  );
}

function Stat({ label, value, hint, bad }: { label: string; value: ReactNode; hint?: string; bad?: boolean }) {
  return (
    <div className="flex flex-col gap-0.5">
      <span className="text-[10px] font-medium uppercase tracking-wider text-muted">{label}</span>
      <span className={cn("font-mono text-lg leading-none", bad ? "text-warning" : "text-fg")}>{value}</span>
      {hint && <span className="font-mono text-[10px] text-faint">{hint}</span>}
    </div>
  );
}

function Ranking({ title, rows, mono = true }: { title: string; rows: RankEntry[]; mono?: boolean }) {
  const fractions = barFractions(rows.map((r) => r.bytes));
  return (
    <Panel title={title} bodyClassName="p-3">
      {rows.length === 0 ? (
        <p className="text-xs text-faint">No data yet</p>
      ) : (
        <ol className="flex flex-col gap-1.5">
          {rows.map((r, i) => (
            <li key={r.key} className="relative overflow-hidden rounded-sm text-xs">
              <div className="absolute inset-y-0 left-0 bg-primary-muted/25" style={{ width: `${fractions[i] * 100}%` }} />
              <div className="relative flex items-center justify-between gap-3 px-2 py-1">
                <span className={cn("truncate", mono && "font-mono")} title={r.key}>
                  {r.key}
                </span>
                <span className="shrink-0 font-mono text-muted">{formatBytes(r.bytes)}</span>
              </div>
            </li>
          ))}
        </ol>
      )}
    </Panel>
  );
}

const LABELS: Record<ProblemLabel, { text: string; tone: BadgeTone }> = {
  potentialIssue: { text: "Potential issue", tone: "warning" },
  unusual: { text: "Unusual", tone: "info" },
  worthInvestigating: { text: "Worth investigating", tone: "neutral" },
};

export function AnalyticsView() {
  const { series, tcp, dns, rankings, problems } = useAnalyticsStore((s) => s.snapshot);
  const health = tcpHealth(tcp);
  const offline = useCaptureStore((s) => s.mode === "offline");
  // Live: the current rate. Offline: the whole file's average, with the peak as context.
  const rate = (key: SeriesKey, format: (n: number) => string) => {
    if (!offline) return { value: format(currentRate(series, key)), hint: undefined };
    const { avg, peak } = summarizeSeries(series, key);
    return { value: format(avg), hint: `avg · peak ${format(peak)}` };
  };
  const pps = rate("packets", formatRate);
  const thr = rate("bytes", (n) => `${(n / 1048576).toFixed(1)} MB/s`);
  const nf = rate("newFlows", (n) => n.toFixed(1));
  return (
    <div className="h-full overflow-auto p-4">
      <div className="mx-auto flex max-w-6xl flex-col gap-4">
        <div className="flex items-center gap-2">
          <ModeBadge />
          {offline && <span className="text-xs text-muted">Charts cover the whole file.</span>}
        </div>
        <section aria-label="Traffic" className="grid grid-cols-2 gap-3 xl:grid-cols-4">
          <Card label="Packets / sec" value={pps.value} hint={pps.hint} values={seriesValues(series, "packets", 300)} />
          <Card label="Throughput" value={thr.value} hint={thr.hint} values={seriesValues(series, "bytes", 300)} tone="text-info" />
          <Card label="Active Flows" value={offline ? formatCount(summarizeSeries(series, "activeFlows").peak) : formatCount(latest(series, "activeFlows"))} hint={offline ? "peak" : undefined} values={seriesValues(series, "activeFlows", 300)} />
          <Card label="New Flows / sec" value={nf.value} hint={nf.hint} values={seriesValues(series, "newFlows", 300)} tone="text-info" />
        </section>

        <div className="grid gap-4 lg:grid-cols-2">
          <Panel title="TCP health" bodyClassName="grid grid-cols-2 gap-4 p-4 sm:grid-cols-4">
            <Stat label="Retransmissions" value={formatCount(tcp.retransmissions)} hint={formatPercent(health.retransmissionRate, 2)} bad={health.retransmissionRate >= 0.01} />
            <Stat label="RST" value={formatCount(tcp.resets)} hint={formatPercent(health.resetRate, 2)} />
            <Stat label="Duplicate ACK" value={formatCount(tcp.duplicateAcks)} />
            <Stat label="Zero window" value={formatCount(tcp.zeroWindows)} />
          </Panel>
          <Panel title="DNS" bodyClassName="grid grid-cols-2 gap-4 p-4 sm:grid-cols-4">
            <Stat label="Avg latency" value={formatLatency(dns.avgLatency)} />
            <Stat label="p95 latency" value={formatLatency(dns.p95Latency)} bad={(dns.p95Latency ?? 0) > 100_000} />
            <Stat label="Failures" value={formatCount(dns.failures)} bad={dns.failures > 0} />
            <Stat label="Queries" value={formatCount(dns.queries)} />
          </Panel>
        </div>

        <Panel title="Potential Problems" bodyClassName="p-3">
          {problems.length === 0 ? (
            <p className="flex items-center gap-2 text-xs text-muted">
              <CheckCircle2 size={14} className="text-primary" /> Nothing unusual has been observed so far.
            </p>
          ) : (
            <ul className="flex flex-col gap-2">
              {problems.map((p) => (
                <li key={p.id} className="flex gap-3 rounded border border-line bg-bg px-3 py-2">
                  <AlertTriangle size={15} className="mt-0.5 shrink-0 text-warning" />
                  <div className="min-w-0">
                    <p className="flex items-center gap-2 text-[13px]">
                      {p.title} <Badge tone={LABELS[p.label].tone}>{LABELS[p.label].text}</Badge>
                    </p>
                    <p className="text-xs text-muted">{p.detail}</p>
                  </div>
                </li>
              ))}
            </ul>
          )}
        </Panel>

        <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
          <Ranking title="Top hosts" rows={rankings.hosts} />
          <Ranking title="Top domains" rows={rankings.domains} />
          <Ranking title="Top talkers (sent)" rows={rankings.talkers} />
          <Ranking title="Top protocols" rows={rankings.protocols} mono={false} />
          <Ranking title="Top ports" rows={rankings.ports} />
        </div>
      </div>
    </div>
  );
}
