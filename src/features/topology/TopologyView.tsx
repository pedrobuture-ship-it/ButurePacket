import { useMemo, useState } from "react";
import { Network } from "lucide-react";
import { EmptyState, ResizablePanel, Select } from "@/components/ui";
import { cn } from "@/lib/cn";
import { flowProtocolLabel } from "@/features/flows/flowText";
import { flowBuffer, useFlowsStore } from "@/stores/flows";
import { useCaptureStore } from "@/stores/capture";
import { DEFAULT_OPTIONS, buildGraph } from "./graph";
import { MapCanvas, type Selection } from "./MapCanvas";
import { EdgeInspector, EmptyInspector, NodeInspector } from "./TopologyInspector";

type Scope = "all" | "local" | "remote";

const THRESHOLDS = [
  { value: "0", label: "Any traffic" },
  { value: "1024", label: "> 1 KB" },
  { value: "102400", label: "> 100 KB" },
  { value: "1048576", label: "> 1 MB" },
  { value: "10485760", label: "> 10 MB" },
];

const LEGEND = [
  ["This Device", "bg-primary"],
  ["Local Device", "bg-primary-muted"],
  ["Remote Host", "bg-info"],
  ["Domain", "bg-warning"],
] as const;

export function TopologyView() {
  const version = useFlowsStore((s) => s.version);
  const interfaces = useCaptureStore((s) => s.interfaces);
  const selectedInterface = useCaptureStore((s) => s.selectedInterface);
  const [scope, setScope] = useState<Scope>("all");
  const [protocol, setProtocol] = useState("");
  const [threshold, setThreshold] = useState("0");
  const [selection, setSelection] = useState<Selection | null>(null);

  const localIps = useMemo(() => new Set(interfaces.find((i) => i.name === selectedInterface)?.addresses ?? []), [interfaces, selectedInterface]);
  const protocols = useMemo(() => [...new Set([...flowBuffer.byId.values()].map(flowProtocolLabel))].sort(), [version]); // eslint-disable-line react-hooks/exhaustive-deps
  const graph = useMemo(
    () => buildGraph(flowBuffer.byId.values(), { ...DEFAULT_OPTIONS, localIps, localOnly: scope === "local", remoteOnly: scope === "remote", protocol: protocol || null, minBytes: Number(threshold) }),
    [version, localIps, scope, protocol, threshold], // eslint-disable-line react-hooks/exhaustive-deps
  );

  const node = selection?.type === "node" ? graph.nodes.find((n) => n.id === selection.id) : undefined;
  const edge = selection?.type === "edge" ? graph.edges.find((e) => e.id === selection.id) : undefined;

  return (
    <div className="flex h-full min-h-0">
      <div className="flex min-w-0 flex-1 flex-col">
        <div className="flex h-10 shrink-0 items-center gap-3 border-b border-line px-3 text-xs">
          <div role="group" aria-label="Scope" className="flex overflow-hidden rounded border border-line-strong">
            {(["all", "local", "remote"] as const).map((s) => (
              <button key={s} type="button" aria-pressed={scope === s} onClick={() => setScope(s)} className={cn("px-2.5 py-1 capitalize transition-colors duration-150", scope === s ? "bg-primary-muted/40 text-fg" : "text-muted hover:bg-hover")}>
                {s === "all" ? "All" : s === "local" ? "Local only" : "Remote only"}
              </button>
            ))}
          </div>
          <Select aria-label="Protocol" value={protocol} options={[{ value: "", label: "All protocols" }, ...protocols.map((p) => ({ value: p, label: p }))]} onChange={(e) => setProtocol(e.target.value)} />
          <Select aria-label="Traffic threshold" value={threshold} options={THRESHOLDS} onChange={(e) => setThreshold(e.target.value)} />
          <div className="flex-1" />
          <span className="font-mono text-muted">
            {graph.nodes.length} nodes · {graph.edges.length} links{graph.clustered > 0 && ` · ${graph.clustered} hosts grouped`}
          </span>
        </div>
        <div className="relative min-h-0 flex-1">
          <MapCanvas graph={graph} selected={selection} onSelect={setSelection} />
          {graph.nodes.length === 0 && (
            <div className="pointer-events-none absolute inset-0">
              <EmptyState icon={<Network size={28} />} title="No connections yet" description="Hosts and connections appear here as flows are captured." />
            </div>
          )}
          <div className="pointer-events-none absolute left-3 top-3 flex gap-3 rounded border border-line bg-surface/80 px-2.5 py-1.5 text-[11px] text-muted">
            {LEGEND.map(([label, dot]) => (
              <span key={label} className="flex items-center gap-1.5">
                <span className={cn("h-2 w-2 rounded-full", dot)} />
                {label}
              </span>
            ))}
          </div>
        </div>
      </div>
      <ResizablePanel id="map-inspector" side="left" defaultSize={320} min={260} max={560} className="overflow-auto border-l border-line bg-surface">
        {node ? <NodeInspector node={node} graph={graph} /> : edge ? <EdgeInspector edge={edge} graph={graph} /> : <EmptyInspector />}
      </ResizablePanel>
    </div>
  );
}
