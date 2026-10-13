import { Badge, EmptyState } from "@/components/ui";
import { formatBytes, formatCount, formatSpan, formatTimestamp } from "@/lib/format";
import { useFlowsStore } from "@/stores/flows";
import { useUiStore } from "@/stores/ui";
import type { Graph, GraphEdge, GraphNode } from "./graph";

function Rows({ rows }: { rows: [string, string | number][] }) {
  return (
    <dl className="selectable grid grid-cols-[minmax(90px,38%)_1fr] gap-x-3 gap-y-1 text-xs">
      {rows.map(([k, v]) => (
        <div key={k} className="col-span-2 grid grid-cols-subgrid">
          <dt className="text-muted">{k}</dt>
          <dd className="break-all font-mono text-fg">{v}</dd>
        </div>
      ))}
    </dl>
  );
}

const KIND_LABEL = { this: "This Device", local: "Local Device", remote: "Remote Host", domain: "Domain", cluster: "Grouped hosts" } as const;

export function NodeInspector({ node, graph }: { node: GraphNode; graph: Graph }) {
  const edges = graph.edges.filter((e) => e.kind === "flow" && (e.source === node.id || e.target === node.id));
  const label = (id: string) => graph.nodes.find((n) => n.id === id)?.label ?? id;
  return (
    <div className="flex flex-col gap-3 p-3">
      <div className="flex items-center gap-2">
        <Badge tone={node.kind === "this" ? "primary" : node.kind === "remote" ? "info" : "neutral"}>{KIND_LABEL[node.kind]}</Badge>
      </div>
      <Rows
        rows={[
          ["IP", node.ip ?? "—"],
          ["Hostname", node.kind === "domain" ? node.label : (node.domains[0] ?? "Unavailable")],
          ["First seen", formatTimestamp(node.firstSeen)],
          ["Last seen", formatTimestamp(node.lastSeen)],
          ["Traffic", formatBytes(node.bytes)],
          ["Flows", formatCount(node.flows)],
          ...(node.members ? [["Hosts grouped", formatCount(node.members)] satisfies [string, string]] : []),
        ]}
      />
      {node.domains.length > 0 && node.kind !== "domain" && (
        <div>
          <p className="mb-1 text-[10px] font-medium uppercase tracking-wider text-muted">Domains</p>
          <ul className="selectable font-mono text-xs">
            {node.domains.map((d) => (
              <li key={d}>{d}</li>
            ))}
          </ul>
          <p className="mt-1 text-[11px] text-muted">Names come from TLS SNI and recent DNS answers; an address can serve many domains.</p>
        </div>
      )}
      <div>
        <p className="mb-1 text-[10px] font-medium uppercase tracking-wider text-muted">Connections ({edges.length})</p>
        <ul className="font-mono text-xs">
          {edges.slice(0, 30).map((e) => (
            <li key={e.id} className="flex justify-between gap-2">
              <span className="truncate">{label(e.source === node.id ? e.target : e.source)}</span>
              <span className="shrink-0 text-muted">{formatBytes(e.bytes)}</span>
            </li>
          ))}
        </ul>
      </div>
    </div>
  );
}

export function EdgeInspector({ edge, graph }: { edge: GraphEdge; graph: Graph }) {
  const select = useFlowsStore((s) => s.select);
  const setView = useUiStore((s) => s.setView);
  const label = (id: string) => graph.nodes.find((n) => n.id === id)?.label ?? id;
  return (
    <div className="flex flex-col gap-3 p-3">
      <p className="font-mono text-xs">
        {label(edge.source)} <span className="text-muted">↔</span> {label(edge.target)}
      </p>
      {edge.kind === "domain" ? (
        <p className="text-xs text-muted">This host was associated with the domain through TLS SNI or a recent DNS answer.</p>
      ) : (
        <>
          <Rows
            rows={[
              ["Flows", formatCount(edge.flows)],
              ["Protocol", edge.protocols.join(", ")],
              ["Bytes", formatBytes(edge.bytes)],
              ["Packets", formatCount(edge.packets)],
              ["Duration", formatSpan(edge.duration)],
              ["First seen", formatTimestamp(edge.startedAt)],
              ["Last seen", formatTimestamp(edge.lastSeenAt)],
            ]}
          />
          {edge.flowIds.length > 0 && (
            <button
              type="button"
              className="self-start rounded border border-line-strong bg-raised px-2.5 py-1 text-xs hover:bg-hover"
              onClick={() => {
                select(edge.flowIds[0]);
                setView("flows");
              }}
            >
              Open flow #{edge.flowIds[0]}
            </button>
          )}
        </>
      )}
    </div>
  );
}

export function EmptyInspector() {
  return <EmptyState title="Nothing selected" description="Select a node or a connection to see details." />;
}
