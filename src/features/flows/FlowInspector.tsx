import { useMemo, useState } from "react";
import { ArrowDown, ArrowUp } from "lucide-react";
import { Badge, EmptyState, Sparkline, Tabs } from "@/components/ui";
import { formatBytes, formatCount, formatLatency, formatSpan, formatTimestamp } from "@/lib/format";
import { packetBuffer } from "@/stores/packets";
import { usePacketsStore } from "@/stores/packets";
import { useUiStore } from "@/stores/ui";
import type { FlowView } from "@/types/ipc";
import { UNAVAILABLE, endpointText, flowProblems, flowProtocolLabel, tlsSummary } from "./flowText";

type Tab = "overview" | "timeline" | "packets" | "dns" | "transport" | "tls" | "problems";

const TABS: { id: Tab; label: string }[] = [
  { id: "overview", label: "Overview" },
  { id: "timeline", label: "Timeline" },
  { id: "packets", label: "Packets" },
  { id: "dns", label: "DNS" },
  { id: "transport", label: "Transport" },
  { id: "tls", label: "TLS" },
  { id: "problems", label: "Problems" },
];

function Rows({ rows }: { rows: [string, string | number][] }) {
  return (
    <dl className="selectable grid grid-cols-[minmax(110px,40%)_1fr] gap-x-3 gap-y-1 text-xs">
      {rows.map(([k, v]) => (
        <div key={k} className="col-span-2 grid grid-cols-subgrid">
          <dt className="text-muted">{k}</dt>
          <dd className="break-all font-mono text-fg">{v}</dd>
        </div>
      ))}
    </dl>
  );
}

function Endpoint({ role, flow, side }: { role: "CLIENT" | "SERVER"; flow: FlowView; side: "a" | "b" }) {
  const e = side === "a" ? flow.endpointA : flow.endpointB;
  return (
    <div className="flex flex-col items-center gap-0.5">
      <span className="text-[10px] font-semibold tracking-widest text-muted">{role}</span>
      <span className="selectable font-mono text-sm text-fg">{endpointText(e)}</span>
      {e.port > 0 && <span className="font-mono text-[11px] text-faint">port {e.port}</span>}
    </div>
  );
}

function Diagram({ flow }: { flow: FlowView }) {
  return (
    <div className="flex flex-col items-center gap-2 rounded border border-line bg-bg px-3 py-4">
      <Endpoint role="CLIENT" flow={flow} side="a" />
      <div className="flex flex-col items-start gap-0.5 font-mono text-xs">
        <span className="flex items-center gap-1.5 text-info">
          <ArrowUp size={13} /> {formatBytes(flow.bytesAToB)} <span className="text-faint">({formatCount(flow.packetsAToB)} pkts)</span>
        </span>
        <span className="flex items-center gap-1.5 text-primary">
          <ArrowDown size={13} /> {formatBytes(flow.bytesBToA)} <span className="text-faint">({formatCount(flow.packetsBToA)} pkts)</span>
        </span>
      </div>
      <Endpoint role="SERVER" flow={flow} side="b" />
    </div>
  );
}

function PacketsTab({ flow }: { flow: FlowView }) {
  const count = usePacketsStore((s) => s.count);
  const select = usePacketsStore((s) => s.select);
  const setView = useUiStore((s) => s.setView);
  const LIMIT = 300;
  const { rows, total } = useMemo(() => {
    const out = [];
    let total = 0;
    for (let i = 0; i < packetBuffer.rows.length; i++) {
      const p = packetBuffer.rows[i];
      if (p.flowId !== flow.id) continue;
      total++;
      if (out.length < LIMIT) out.push(p);
    }
    return { rows: out, total };
    // `count` changes as packets arrive
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [flow.id, count]);
  if (rows.length === 0) return <EmptyState title="No packets in memory" description="Packets of this flow are not available in the current buffer." />;
  return (
    <div className="flex flex-col gap-1">
      <p className="text-xs text-muted">
        Showing {formatCount(rows.length)} of {formatCount(total)} packets
      </p>
      {rows.map((p) => (
        <button
          key={p.id}
          type="button"
          onClick={() => {
            select(p.id);
            setView("packets");
          }}
          className="flex gap-2 rounded px-1 py-0.5 text-left font-mono text-[11px] hover:bg-hover"
        >
          <span className="w-12 shrink-0 text-muted">#{p.id}</span>
          <span className="w-24 shrink-0 text-muted">{formatTimestamp(p.timestamp)}</span>
          <span className="truncate">{p.info}</span>
        </button>
      ))}
    </div>
  );
}

function TlsTab({ flow }: { flow: FlowView }) {
  const t = flow.tls;
  if (!t) return <EmptyState title="TLS metadata unavailable" description="No TLS handshake was observed for this flow." />;
  const cert = t.certificate;
  const na = (v: string | null | undefined) => v ?? UNAVAILABLE;
  return (
    <div className="flex flex-col gap-4">
      <div className="rounded border border-line bg-bg px-3 py-2.5 font-mono text-sm">
        {tlsSummary(flow).map((line) => (
          <div key={line} className={line.endsWith(UNAVAILABLE) ? "text-faint" : "text-fg"}>
            {line}
          </div>
        ))}
      </div>
      <Rows
        rows={[
          ["Negotiated version", na(t.version)],
          ["Cipher suite", na(t.cipherSuite)],
          ["ALPN offered", t.alpnOffered.length ? t.alpnOffered.join(", ") : UNAVAILABLE],
          ["ALPN selected", na(t.alpnSelected)],
          ["Client Hello", t.clientHelloAt ? formatTimestamp(t.clientHelloAt) : UNAVAILABLE],
          ["Server Hello", t.serverHelloAt ? formatTimestamp(t.serverHelloAt) : UNAVAILABLE],
        ]}
      />
      {cert ? (
        <Rows
          rows={[
            ["Certificate subject", na(cert.subjectCn)],
            ["Issuer", na(cert.issuerCn)],
            ["Valid from", na(cert.notBefore)],
            ["Valid until", na(cert.notAfter)],
            ["Alternative names", cert.dnsNames.length ? cert.dnsNames.join(", ") : UNAVAILABLE],
          ]}
        />
      ) : (
        <p className="text-xs text-muted">{t.handshakeEncrypted ? "Certificate: Unavailable — TLS 1.3 encrypts it." : "Certificate: Unavailable — not seen in the captured handshake."}</p>
      )}
    </div>
  );
}

export function FlowInspector({ flow }: { flow: FlowView }) {
  const [tab, setTab] = useState<Tab>("overview");
  const problems = flowProblems(flow);
  return (
    <div className="flex h-full min-h-0 flex-col">
      <div className="flex shrink-0 items-center gap-2 border-b border-line px-3 py-2">
        <Badge>{flowProtocolLabel(flow)}</Badge>
        <span className="truncate font-mono text-xs text-fg">
          {endpointText(flow.endpointA, true)} → {endpointText(flow.endpointB, true)}
        </span>
      </div>
      <Tabs tabs={TABS.map((t) => (t.id === "problems" && problems.length ? { ...t, label: `Problems (${problems.length})` } : t))} value={tab} onChange={setTab} className="shrink-0 px-1" />
      <div className="min-h-0 flex-1 overflow-auto p-3">
        {tab === "overview" && (
          <div className="flex flex-col gap-4">
            <Diagram flow={flow} />
            <div>
              <p className="mb-1 text-[10px] font-medium uppercase tracking-wider text-muted">Traffic · last 60 s</p>
              <Sparkline values={flow.sparkline} width={300} height={40} className="w-full" />
            </div>
            <Rows
              rows={[
                ["Protocol", flow.protocol],
                ["Started", formatTimestamp(flow.startedAt)],
                ["Duration", formatSpan(flow.duration)],
                ["Packets", formatCount(flow.totalPackets)],
                ["Total traffic", formatBytes(flow.totalBytes)],
                ["Latency", formatLatency(flow.latency)],
                ["State", flow.tcpState ?? "—"],
                ["Process", flow.process ?? "Unavailable"],
              ]}
            />
          </div>
        )}
        {tab === "timeline" && <EmptyState title="Timeline" description="Per-flow events are shown here once the event timeline is available." />}
        {tab === "packets" && <PacketsTab flow={flow} />}
        {tab === "dns" &&
          (flow.domains.length ? (
            <div className="flex flex-col gap-2 text-xs">
              <ul className="selectable flex flex-col gap-1 font-mono">
                {flow.domains.map((d) => (
                  <li key={d}>
                    <span className="text-muted">Likely domain:</span> {d}
                  </li>
                ))}
              </ul>
              <p className="text-muted">Inferred from DNS answers seen shortly before this flow started. A shared address can serve many domains, so treat this as a hint, not proof.</p>
            </div>
          ) : (
            <EmptyState title="No domain observed" description="No DNS answer matching this flow's address was captured." />
          ))}
        {tab === "transport" && (
          <Rows
            rows={[
              ["Protocol", flow.protocol],
              ["TCP state", flow.tcpState ?? "—"],
              ["Handshake RTT", formatLatency(flow.latency)],
              ["Retransmissions", flow.retransmissions],
              ["Duplicate ACKs", flow.duplicateAcks],
              ["Zero windows", flow.zeroWindows],
              ["Resets", flow.resets],
            ]}
          />
        )}
        {tab === "tls" && <TlsTab flow={flow} />}
        {tab === "problems" &&
          (problems.length ? (
            <ul className="flex flex-col gap-2 text-xs">
              {problems.map((p) => (
                <li key={p} className="rounded border border-warning/40 bg-warning/10 px-2 py-1.5 text-warning">
                  {p}
                </li>
              ))}
            </ul>
          ) : (
            <EmptyState title="No issues observed" description="Nothing unusual was seen in this flow." />
          ))}
      </div>
    </div>
  );
}
