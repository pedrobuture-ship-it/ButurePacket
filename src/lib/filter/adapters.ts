import type { DnsTransaction, FlowView, PacketSummary, TimelineEvent } from "@/types/ipc";
import type { FieldValue, Subject } from "./evaluate";

const lower = (s: string | null | undefined): string | undefined => (s ? s.toLowerCase() : undefined);
const compact = <T>(xs: (T | null | undefined)[]): T[] => xs.filter((x): x is T => x !== null && x !== undefined);

/** Adapters are reusable: point `item` at the next row instead of allocating a subject per row. */
export class PacketSubject implements Subject {
  item!: PacketSummary;
  constructor(private readonly flowOf: (id: number) => FlowView | undefined) {}

  private flow(): FlowView | undefined {
    return this.item.flowId === null ? undefined : this.flowOf(this.item.flowId);
  }

  get(field: string): FieldValue {
    const p = this.item;
    switch (field) {
      case "ip":
        return compact([p.sourceIp, p.destinationIp]);
      case "src.ip":
        return p.sourceIp ?? undefined;
      case "dst.ip":
        return p.destinationIp ?? undefined;
      case "port":
        return compact([p.sourcePort, p.destinationPort]);
      case "src.port":
        return p.sourcePort ?? undefined;
      case "dst.port":
        return p.destinationPort ?? undefined;
      case "mac":
        return compact([p.sourceMac, p.destinationMac]);
      case "src.mac":
        return p.sourceMac ?? undefined;
      case "dst.mac":
        return p.destinationMac ?? undefined;
      case "length":
      case "bytes":
        return p.capturedLength;
      case "ttl":
        return p.ttl ?? undefined;
      case "flags":
        return p.tcpFlags?.map((f) => f.toLowerCase());
      case "info":
        return p.info;
      case "flow":
        return p.flowId ?? undefined;
      case "latency":
        return p.latency ?? this.flow()?.latency ?? undefined;
      case "domain": {
        const f = this.flow();
        return compact([p.domain, f?.tls?.sni, ...(f?.domains ?? [])]);
      }
      case "sni":
        return this.flow()?.tls?.sni ?? undefined;
      case "state":
        return lower(this.flow()?.tcpState);
      case "duration":
        return this.flow()?.duration;
      case "packets":
        return this.flow()?.totalPackets;
      default:
        return undefined;
    }
  }

  protocols(): readonly string[] {
    const p = this.item;
    const out = compact([lower(p.networkProtocol), lower(p.transportProtocol), lower(p.applicationProtocol)]);
    if (out.includes("ipv4") || out.includes("ipv6")) out.push("ip");
    return out;
  }
}

export class FlowSubject implements Subject {
  item!: FlowView;

  get(field: string): FieldValue {
    const f = this.item;
    switch (field) {
      case "ip":
        return [f.endpointA.ip, f.endpointB.ip];
      case "src.ip":
        return f.endpointA.ip;
      case "dst.ip":
        return f.endpointB.ip;
      case "port":
        return [f.endpointA.port, f.endpointB.port];
      case "src.port":
        return f.endpointA.port;
      case "dst.port":
        return f.endpointB.port;
      case "bytes":
        return f.totalBytes;
      case "packets":
        return f.totalPackets;
      case "duration":
        return f.duration;
      case "latency":
        return f.latency ?? undefined;
      case "state":
        return lower(f.tcpState);
      case "flow":
        return f.id;
      case "domain":
        return compact([f.tls?.sni, ...f.domains]);
      case "sni":
        return f.tls?.sni ?? undefined;
      default:
        return undefined;
    }
  }

  protocols(): readonly string[] {
    const f = this.item;
    const out = compact([lower(f.protocol), lower(f.applicationProtocol), "ip"]);
    return out;
  }
}

export class DnsSubject implements Subject {
  item!: DnsTransaction;

  get(field: string): FieldValue {
    const t = this.item;
    switch (field) {
      case "ip":
        return [t.client, t.resolver];
      case "src.ip":
        return t.client;
      case "dst.ip":
      case "resolver":
        return t.resolver;
      case "domain":
        return t.queryName;
      case "latency":
        return t.latency ?? undefined;
      case "rcode":
        return lower(t.responseCode);
      case "type":
        return t.queryType.toLowerCase();
      case "status":
        return t.status;
      case "flow":
        return t.flowId ?? undefined;
      default:
        return undefined;
    }
  }

  protocols(): readonly string[] {
    return ["dns"];
  }
}

export class EventSubject implements Subject {
  item!: TimelineEvent;

  get(field: string): FieldValue {
    const e = this.item;
    switch (field) {
      case "ip":
        return compact([e.host]);
      case "dst.ip":
        return e.host ?? undefined;
      case "domain":
        return compact([e.domain]);
      case "flow":
        return e.flowId ?? undefined;
      case "type":
        return e.kind.toLowerCase();
      case "info":
        return `${e.title} ${e.detail ?? ""}`.trim();
      default:
        return undefined;
    }
  }

  protocols(): readonly string[] {
    if (isEventGroup(this.item, "dns")) return ["dns"];
    if (isEventGroup(this.item, "tls")) return ["tls", "tcp"];
    if (isEventGroup(this.item, "tcp")) return ["tcp"];
    return [];
  }
}

function isEventGroup(e: TimelineEvent, group: "dns" | "tls" | "tcp"): boolean {
  if (group === "dns") return e.kind.startsWith("dns");
  if (group === "tls") return e.kind === "tlsHandshake";
  return ["flowStarted", "tcpConnect", "flowEnded", "retransmission", "reset"].includes(e.kind);
}
