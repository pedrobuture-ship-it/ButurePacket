export type FieldKind = "ip" | "port" | "string" | "number" | "size" | "duration" | "mac" | "protocol" | "flags";

export interface FieldDef {
  name: string;
  kind: FieldKind;
  description: string;
  aliases?: string[];
}

export const FIELDS: FieldDef[] = [
  { name: "ip", kind: "ip", description: "Source or destination address (CIDR ok)" },
  { name: "src.ip", kind: "ip", description: "Source address" },
  { name: "dst.ip", kind: "ip", description: "Destination address" },
  { name: "port", kind: "port", description: "Source or destination port" },
  { name: "src.port", kind: "port", description: "Source port" },
  { name: "dst.port", kind: "port", description: "Destination port" },
  { name: "protocol", kind: "protocol", description: "Any protocol layer", aliases: ["proto"] },
  { name: "mac", kind: "mac", description: "Source or destination MAC" },
  { name: "src.mac", kind: "mac", description: "Source MAC" },
  { name: "dst.mac", kind: "mac", description: "Destination MAC" },
  { name: "length", kind: "size", description: "Packet length", aliases: ["len"] },
  { name: "bytes", kind: "size", description: "Bytes (flow total / packet length)" },
  { name: "packets", kind: "number", description: "Packet count of a flow" },
  { name: "ttl", kind: "number", description: "IP time to live / hop limit" },
  { name: "flags", kind: "flags", description: "TCP flags (syn, ack, fin, rst…)" },
  { name: "info", kind: "string", description: "Packet info text" },
  { name: "domain", kind: "string", description: "Domain (DNS query, TLS SNI, likely domain)" },
  { name: "sni", kind: "string", description: "TLS server name" },
  { name: "latency", kind: "duration", description: "DNS or TCP handshake latency" },
  { name: "duration", kind: "duration", description: "Flow duration" },
  { name: "state", kind: "string", description: "TCP state" },
  { name: "flow", kind: "number", description: "Flow id" },
  { name: "resolver", kind: "ip", description: "DNS resolver address" },
  { name: "rcode", kind: "string", description: "DNS response code" },
  { name: "type", kind: "string", description: "DNS query type / event kind" },
  { name: "status", kind: "string", description: "DNS status" },
];

const BY_NAME = new Map<string, FieldDef>();
for (const f of FIELDS) {
  BY_NAME.set(f.name, f);
  for (const a of f.aliases ?? []) BY_NAME.set(a, f);
}

export function lookupField(name: string): FieldDef | undefined {
  return BY_NAME.get(name.toLowerCase());
}

export const PROTOCOLS = ["tcp", "udp", "icmp", "icmpv6", "arp", "ip", "ipv4", "ipv6", "dns", "tls", "http", "quic", "ssh", "dhcp", "ntp", "mdns"];

/** Words accepted on their own as a protocol match. */
const PROTOCOL_ALIASES: Record<string, string> = { https: "tls", ssl: "tls" };

export function normalizeProtocol(word: string): string | null {
  const w = word.toLowerCase();
  const canonical = PROTOCOL_ALIASES[w] ?? w;
  return PROTOCOLS.includes(canonical) ? canonical : null;
}

export const TCP_FLAGS = ["syn", "ack", "fin", "rst", "psh", "urg", "ece", "cwr"];

export type Operator = "=" | "!=" | ">" | ">=" | "<" | "<=" | "contains" | "startswith" | "endswith";

const ORDERED: Operator[] = ["=", "!=", ">", ">=", "<", "<="];
const TEXT: Operator[] = ["=", "!=", "contains", "startswith", "endswith"];

export const OPERATORS_BY_KIND: Record<FieldKind, Operator[]> = {
  ip: ["=", "!="],
  port: ORDERED,
  number: ORDERED,
  size: ORDERED,
  duration: ORDERED,
  string: TEXT,
  mac: ["=", "!=", "contains"],
  protocol: ["=", "!="],
  flags: ["=", "!=", "contains"],
};

/** Edit distance, for "did you mean" hints. */
export function distance(a: string, b: string): number {
  const dp = Array.from({ length: a.length + 1 }, (_, i) => [i, ...new Array<number>(b.length).fill(0)]);
  for (let j = 1; j <= b.length; j++) dp[0][j] = j;
  for (let i = 1; i <= a.length; i++) {
    for (let j = 1; j <= b.length; j++) dp[i][j] = Math.min(dp[i - 1][j] + 1, dp[i][j - 1] + 1, dp[i - 1][j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
  }
  return dp[a.length][b.length];
}

export function closestField(name: string): string | null {
  const n = name.toLowerCase();
  let best: [number, string] | null = null;
  for (const key of [...BY_NAME.keys(), ...PROTOCOLS]) {
    const d = distance(n, key);
    if (d <= Math.max(1, Math.floor(key.length / 3)) && (!best || d < best[0])) best = [d, key];
  }
  return best ? best[1] : null;
}
