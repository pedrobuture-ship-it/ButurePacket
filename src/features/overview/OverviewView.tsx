import { useMemo } from "react";
import { AlertTriangle, ArrowRight, CheckCircle2 } from "lucide-react";
import { ModeBadge } from "@/components/ModeBadge";
import { AreaChart, Badge, Button, EmptyState, Metric, Panel } from "@/components/ui";
import { flowProtocolLabel, endpointText } from "@/features/flows/flowText";
import { StoryPanel } from "@/features/story/StoryPanel";
import { cn } from "@/lib/cn";
import { formatBytes, formatCount, formatDuration } from "@/lib/format";
import { sanitizeText } from "@/lib/sanitize";
import { protocolTone } from "@/lib/protocolColors";
import { formatClock } from "@/features/timeline/model";
import { latest, seriesValues } from "@/features/analytics/derive";
import { useAnalyticsStore } from "@/stores/analytics";
import { useCaptureStore } from "@/stores/capture";
import { flowBuffer, useFlowsStore } from "@/stores/flows";
import { useUiStore } from "@/stores/ui";
import { distribution, pickStoryFlow, topConnections, uniqueDomains } from "./model";

const SLICE_COLORS = ["var(--color-primary)", "var(--color-info)", "var(--color-warning)", "#a78bfa", "var(--color-primary-muted)", "var(--color-faint)"];

function Header() {
  const { mode, selectedInterface, fileName, stats } = useCaptureStore();
  return (
    <header className="flex items-center gap-4 border-b border-line px-4 py-3">
      <ModeBadge />
      <span className="font-mono text-sm text-fg">{sanitizeText(mode === "live" ? (selectedInterface ?? "—") : (fileName ?? "—"))}</span>
      <span className="font-mono text-sm text-muted">{formatDuration(stats.durationMs)}</span>
    </header>
  );
}

export function OverviewView() {
  const version = useFlowsStore((s) => s.version);
  const stats = useCaptureStore((s) => s.stats);
  const { series, rankings, problems } = useAnalyticsStore((s) => s.snapshot);
  const setView = useUiStore((s) => s.setView);
  const selectFlow = useFlowsStore((s) => s.select);

  const { top, story, domains } = useMemo(() => {
    const flows = [...flowBuffer.byId.values()];
    return { top: topConnections(flows), story: pickStoryFlow(flows), domains: uniqueDomains(flows) };
  }, [version]); // eslint-disable-line react-hooks/exhaustive-deps

  const slices = distribution(rankings.protocols);
  const empty = stats.packets === 0 && flowBuffer.byId.size === 0;
  const up = seriesValues(series, "bytesUp", 300);
  const down = seriesValues(series, "bytesDown", 300);
  const first = series[0]?.sec;
  const last = series.length ? series[series.length - 1].sec + series[series.length - 1].span : undefined;

  const openFlow = (id: number) => {
    selectFlow(id);
    setView("flows");
  };

  return (
    <div className="flex h-full min-h-0 flex-col overflow-auto">
      <Header />
      <div className="flex flex-col gap-4 p-4">
        <div className="flex flex-wrap gap-x-10 gap-y-3">
          <Metric label="Packets" value={formatCount(stats.packets)} />
          <Metric label="Traffic" value={formatBytes(stats.bytes)} />
          <Metric label="Active Flows" value={formatCount(latest(series, "activeFlows"))} hint={`${formatCount(flowBuffer.byId.size)} total`} />
          <Metric label="Domains" value={formatCount(domains)} />
        </div>

        {empty ? (
          <Panel>
            <EmptyState title="Nothing captured yet" description="Start a capture on an interface or open a PCAP file. A summary of what happened on the network will appear here." />
          </Panel>
        ) : (
          <>
            <Panel title="Network Activity" bodyClassName="p-3">
              <div className="mb-2 flex gap-4 text-[11px] text-muted">
                <span className="flex items-center gap-1.5">
                  <span className="h-2 w-2 rounded-full bg-info" /> Upload
                </span>
                <span className="flex items-center gap-1.5">
                  <span className="h-2 w-2 rounded-full bg-primary" /> Download
                </span>
              </div>
              <AreaChart
                series={[
                  { label: "Download", values: down, color: "var(--color-primary)" },
                  { label: "Upload", values: up, color: "var(--color-info)" },
                ]}
                formatValue={(v) => `${formatBytes(v)}/s`}
                startLabel={first ? formatClock(first * 1e6, false) : undefined}
                endLabel={last ? formatClock(last * 1e6, false) : undefined}
              />
            </Panel>

            <div className="grid gap-4 lg:grid-cols-[3fr_2fr]">
              <Panel title="Top Connections" actions={<Button size="sm" variant="ghost" icon={<ArrowRight size={12} />} onClick={() => setView("flows")}>All flows</Button>}>
                <ol className="divide-y divide-line/60">
                  {top.map((f) => (
                    <li key={f.id}>
                      <button type="button" onClick={() => openFlow(f.id)} className="grid w-full grid-cols-[64px_1fr_auto] items-center gap-3 px-3 py-1.5 text-left text-xs transition-colors duration-150 hover:bg-hover">
                        <Badge tone={protocolTone(flowProtocolLabel(f))}>{flowProtocolLabel(f)}</Badge>
                        <span className="truncate font-mono">
                          <span className="text-fg">{f.tls?.sni ?? f.domains[0] ?? endpointText(f.endpointB)}</span>
                          <span className="text-faint"> · {endpointText(f.endpointA)} → {endpointText(f.endpointB, true)}</span>
                        </span>
                        <span className="font-mono text-muted">{formatBytes(f.totalBytes)}</span>
                      </button>
                    </li>
                  ))}
                  {top.length === 0 && <li className="px-3 py-3 text-xs text-faint">No flows yet</li>}
                </ol>
              </Panel>

              <Panel title="Protocol Distribution" bodyClassName="p-3">
                {slices.length === 0 ? (
                  <p className="text-xs text-faint">No data yet</p>
                ) : (
                  <>
                    <div role="img" aria-label="Protocol distribution by bytes" className="flex h-2.5 overflow-hidden rounded-sm bg-bg">
                      {slices.map((s, i) => (
                        <div key={s.key} style={{ width: `${s.fraction * 100}%`, background: SLICE_COLORS[i % SLICE_COLORS.length] }} title={`${s.key}: ${formatBytes(s.bytes)}`} />
                      ))}
                    </div>
                    <ul className="mt-3 flex flex-col gap-1">
                      {slices.map((s, i) => (
                        <li key={s.key} className="flex items-center gap-2 font-mono text-xs">
                          <span className="h-2 w-2 shrink-0 rounded-full" style={{ background: SLICE_COLORS[i % SLICE_COLORS.length] }} />
                          <span className="flex-1 truncate">{s.key}</span>
                          <span className="text-muted">{formatBytes(s.bytes)}</span>
                          <span className="w-12 text-right text-faint">{(s.fraction * 100).toFixed(1)}%</span>
                        </li>
                      ))}
                    </ul>
                  </>
                )}
              </Panel>
            </div>

            <div className="grid gap-4 lg:grid-cols-2">
              <Panel title="Recent Network Story" actions={story && <Button size="sm" variant="ghost" icon={<ArrowRight size={12} />} onClick={() => openFlow(story.id)}>Open flow</Button>} bodyClassName="p-3">
                {story ? (
                  <div className="flex flex-col gap-2">
                    <p className="font-mono text-[11px] text-muted">
                      {endpointText(story.endpointA, true)} → {endpointText(story.endpointB, true)}
                    </p>
                    <StoryPanel flow={story} />
                  </div>
                ) : (
                  <p className="text-xs text-faint">A story appears once a connection has been seen.</p>
                )}
              </Panel>

              <Panel title="Potential Problems" bodyClassName="p-3">
                {problems.length === 0 ? (
                  <p className="flex items-center gap-2 text-xs text-muted">
                    <CheckCircle2 size={14} className="text-primary" /> Nothing unusual has been observed so far.
                  </p>
                ) : (
                  <ul className="flex flex-col gap-2">
                    {problems.map((p) => (
                      <li key={p.id} className={cn("flex gap-2.5 rounded border border-line bg-bg px-3 py-2")}>
                        <AlertTriangle size={14} className="mt-0.5 shrink-0 text-warning" />
                        <div className="min-w-0 text-xs">
                          <p className="text-[13px]">{p.title}</p>
                          <p className="text-muted">{p.detail}</p>
                        </div>
                      </li>
                    ))}
                  </ul>
                )}
              </Panel>
            </div>
          </>
        )}
      </div>
    </div>
  );
}
