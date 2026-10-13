import type { FlowView } from "@/types/ipc";
import { flowProtocolLabel } from "@/features/flows/flowText";

export type NodeKind = "this" | "local" | "remote" | "domain" | "cluster";

export interface GraphNode {
  id: string;
  kind: NodeKind;
  label: string;
  /** Only for host nodes. */
  ip?: string;
  bytes: number;
  flows: number;
  firstSeen: number;
  lastSeen: number;
  /** Domains observed for this host (SNI first, then likely DNS names). */
  domains: string[];
  /** For cluster nodes: how many hosts were folded in. */
  members?: number;
  size: number;
}

export interface GraphEdge {
  id: string;
  source: string;
  target: string;
  kind: "flow" | "domain";
  bytes: number;
  packets: number;
  flows: number;
  protocols: string[];
  startedAt: number;
  lastSeenAt: number;
  duration: number;
  flowIds: number[];
}

export interface GraphOptions {
  /** Addresses known to belong to this machine (from the capture interface). */
  localIps: ReadonlySet<string>;
  localOnly: boolean;
  remoteOnly: boolean;
  /** Flow protocol label to keep, or null for all. */
  protocol: string | null;
  /** Hide hosts that moved fewer bytes than this. */
  minBytes: number;
  /** Hard cap on host nodes drawn; the rest are folded into cluster nodes. */
  maxNodes: number;
}

export interface Graph {
  nodes: GraphNode[];
  edges: GraphEdge[];
  /** Host nodes folded into clusters because of `maxNodes`. */
  clustered: number;
}

export const DEFAULT_OPTIONS: GraphOptions = { localIps: new Set(), localOnly: false, remoteOnly: false, protocol: null, minBytes: 0, maxNodes: 150 };
const MAX_DOMAIN_NODES = 60;
const MAX_EDGE_FLOW_IDS = 50;

/** Local = private, link-local, loopback, multicast/broadcast; everything else is remote. */
export function isLocalAddress(ip: string): boolean {
  if (ip.includes(":")) {
    const v = ip.toLowerCase();
    if (v === "::1" || v === "::") return true;
    const first = parseInt(v.split(":")[0] || "0", 16);
    return (first & 0xffc0) === 0xfe80 || (first & 0xfe00) === 0xfc00 || (first & 0xff00) === 0xff00;
  }
  const p = ip.split(".").map(Number);
  if (p.length !== 4 || p.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) return false;
  const [a, b] = p;
  return a === 10 || a === 127 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 169 && b === 254) || (a === 100 && b >= 64 && b <= 127) || a >= 224;
}

interface HostAcc {
  ip: string;
  bytes: number;
  flows: number;
  firstSeen: number;
  lastSeen: number;
  sni: Set<string>;
  likely: Set<string>;
}

const hostId = (ip: string) => `ip:${ip}`;
const pairKey = (a: string, b: string) => (a < b ? `${a}|${b}` : `${b}|${a}`);

function nodeSize(bytes: number, maxBytes: number): number {
  const ratio = maxBytes > 0 ? Math.log10(bytes + 1) / Math.log10(maxBytes + 1) : 0;
  return Math.round(18 + 30 * ratio);
}

export function buildGraph(flows: Iterable<FlowView>, options: GraphOptions): Graph {
  // 1. Accumulate hosts and host-pair edges.
  const hosts = new Map<string, HostAcc>();
  const pairs = new Map<string, GraphEdge>();
  const host = (ip: string, f: FlowView): HostAcc => {
    let h = hosts.get(ip);
    if (!h) hosts.set(ip, (h = { ip, bytes: 0, flows: 0, firstSeen: f.startedAt, lastSeen: f.lastSeenAt, sni: new Set(), likely: new Set() }));
    return h;
  };
  for (const f of flows) {
    const label = flowProtocolLabel(f);
    if (options.protocol && label !== options.protocol) continue;
    const [a, b] = [f.endpointA.ip, f.endpointB.ip];
    for (const ip of [a, b]) {
      const h = host(ip, f);
      h.bytes += f.totalBytes;
      h.flows++;
      h.firstSeen = Math.min(h.firstSeen, f.startedAt);
      h.lastSeen = Math.max(h.lastSeen, f.lastSeenAt);
    }
    // Domains describe the far end (the server), not the client.
    const server = host(b, f);
    if (f.tls?.sni) server.sni.add(f.tls.sni);
    for (const d of f.domains) server.likely.add(d);

    const key = pairKey(a, b);
    let e = pairs.get(key);
    if (!e) {
      const [s, t] = a < b ? [a, b] : [b, a];
      pairs.set(key, (e = { id: `e:${key}`, source: hostId(s), target: hostId(t), kind: "flow", bytes: 0, packets: 0, flows: 0, protocols: [], startedAt: f.startedAt, lastSeenAt: f.lastSeenAt, duration: 0, flowIds: [] }));
    }
    e.bytes += f.totalBytes;
    e.packets += f.totalPackets;
    e.flows++;
    if (!e.protocols.includes(label)) e.protocols.push(label);
    e.startedAt = Math.min(e.startedAt, f.startedAt);
    e.lastSeenAt = Math.max(e.lastSeenAt, f.lastSeenAt);
    if (e.flowIds.length < MAX_EDGE_FLOW_IDS) e.flowIds.push(f.id);
  }

  // 2. Which host is this device? Prefer known interface addresses, else the busiest private host.
  let thisIp: string | null = null;
  for (const h of hosts.values()) if (options.localIps.has(h.ip) && (!thisIp || h.bytes > hosts.get(thisIp)!.bytes)) thisIp = h.ip;
  if (!thisIp) for (const h of hosts.values()) if (isLocalAddress(h.ip) && (!thisIp || h.bytes > hosts.get(thisIp)!.bytes)) thisIp = h.ip;

  const kindOf = (ip: string): NodeKind => (ip === thisIp ? "this" : isLocalAddress(ip) ? "local" : "remote");

  // 3. Filters (this device is always kept so the graph stays anchored).
  let visible = [...hosts.values()].filter((h) => {
    const kind = kindOf(h.ip);
    if (kind === "this") return true;
    if (options.localOnly && kind === "remote") return false;
    if (options.remoteOnly && kind === "local") return false;
    return h.bytes >= options.minBytes;
  });

  // 4. Cap the number of drawn hosts; fold the rest into one cluster per kind.
  visible.sort((x, y) => (kindOf(y.ip) === "this" ? 1 : 0) - (kindOf(x.ip) === "this" ? 1 : 0) || y.bytes - x.bytes || x.ip.localeCompare(y.ip));
  const folded = new Map<string, { kind: "local" | "remote"; members: HostAcc[] }>();
  let clustered = 0;
  if (visible.length > options.maxNodes) {
    for (const h of visible.slice(options.maxNodes)) {
      const kind = kindOf(h.ip) === "local" ? "local" : "remote";
      const c = folded.get(`cluster:${kind}`) ?? { kind, members: [] };
      c.members.push(h);
      folded.set(`cluster:${kind}`, c);
      clustered++;
    }
    visible = visible.slice(0, options.maxNodes);
  }
  const keep = new Set(visible.map((h) => h.ip));
  const clusterOf = new Map<string, string>();
  for (const [id, c] of folded) for (const m of c.members) clusterOf.set(m.ip, id);
  const resolve = (ip: string): string | null => (keep.has(ip) ? hostId(ip) : (clusterOf.get(ip) ?? null));

  // 5. Rebuild edges against the kept/clustered nodes.
  const edges = new Map<string, GraphEdge>();
  for (const e of pairs.values()) {
    const [sIp, tIp] = [e.source.slice(3), e.target.slice(3)];
    const [s, t] = [resolve(sIp), resolve(tIp)];
    if (!s || !t || s === t) continue;
    const key = pairKey(s, t);
    const existing = edges.get(key);
    if (!existing) {
      edges.set(key, { ...e, id: `e:${key}`, source: s < t ? s : t, target: s < t ? t : s, protocols: [...e.protocols], flowIds: [...e.flowIds] });
    } else {
      existing.bytes += e.bytes;
      existing.packets += e.packets;
      existing.flows += e.flows;
      for (const p of e.protocols) if (!existing.protocols.includes(p)) existing.protocols.push(p);
      existing.startedAt = Math.min(existing.startedAt, e.startedAt);
      existing.lastSeenAt = Math.max(existing.lastSeenAt, e.lastSeenAt);
      existing.flowIds.push(...e.flowIds.slice(0, MAX_EDGE_FLOW_IDS - existing.flowIds.length));
    }
  }
  for (const e of edges.values()) e.duration = e.lastSeenAt - e.startedAt;

  // 6. Nodes.
  const maxBytes = Math.max(0, ...visible.map((h) => h.bytes), ...[...folded.values()].map((c) => c.members.reduce((n, m) => n + m.bytes, 0)));
  const nodes: GraphNode[] = visible.map((h) => {
    const domains = [...h.sni, ...[...h.likely].filter((d) => !h.sni.has(d))];
    return { id: hostId(h.ip), kind: kindOf(h.ip), label: domains[0] ?? h.ip, ip: h.ip, bytes: h.bytes, flows: h.flows, firstSeen: h.firstSeen, lastSeen: h.lastSeen, domains, size: nodeSize(h.bytes, maxBytes) };
  });
  for (const [id, c] of folded) {
    const bytes = c.members.reduce((n, m) => n + m.bytes, 0);
    nodes.push({
      id,
      kind: "cluster",
      label: `${c.members.length} more ${c.kind} hosts`,
      bytes,
      flows: c.members.reduce((n, m) => n + m.flows, 0),
      firstSeen: Math.min(...c.members.map((m) => m.firstSeen)),
      lastSeen: Math.max(...c.members.map((m) => m.lastSeen)),
      domains: [],
      members: c.members.length,
      size: nodeSize(bytes, maxBytes),
    });
  }

  // 7. Domain nodes for names beyond the one already used as the host's label (the first, i.e. TLS SNI
  //    when known). Hosts with a single name just carry it as their label.
  const named = nodes.filter((n) => n.kind === "remote" && n.domains.length > 1).sort((a, b) => b.bytes - a.bytes).slice(0, MAX_DOMAIN_NODES);
  const domainNodes = new Map<string, GraphNode>();
  for (const n of named) {
    const d = n.domains[1].toLowerCase();
    const id = `domain:${d}`;
    if (!domainNodes.has(id)) domainNodes.set(id, { id, kind: "domain", label: d, bytes: 0, flows: 0, firstSeen: n.firstSeen, lastSeen: n.lastSeen, domains: [d], size: 14 });
    const dn = domainNodes.get(id)!;
    dn.bytes += n.bytes;
    dn.flows += n.flows;
    dn.firstSeen = Math.min(dn.firstSeen, n.firstSeen);
    dn.lastSeen = Math.max(dn.lastSeen, n.lastSeen);
    edges.set(`d:${id}|${n.id}`, { id: `d:${id}|${n.id}`, source: id, target: n.id, kind: "domain", bytes: 0, packets: 0, flows: 0, protocols: [], startedAt: n.firstSeen, lastSeenAt: n.lastSeen, duration: 0, flowIds: [] });
  }

  return { nodes: [...nodes, ...domainNodes.values()], edges: [...edges.values()], clustered };
}
