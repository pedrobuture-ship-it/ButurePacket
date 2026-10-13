/** Types mirrored from the Rust side (src-tauri/src/commands). Keep in sync. */
export interface AppInfo {
  name: string;
  version: string;
  platform: string;
}

/** Error shape returned by every failing command. */
export interface IpcError {
  kind: string;
  message: string;
}

export type SessionState = "idle" | "running" | "paused" | "stopped" | "error";

export interface StatePayload {
  state: SessionState;
  error: IpcError | null;
}

/** One decoded packet row. The payload is never included; fetch bytes on demand. */
export interface PacketSummary {
  id: number;
  flowId: number | null;
  /** Microseconds since the Unix epoch. */
  timestamp: number;
  capturedLength: number;
  originalLength: number;
  sourceMac: string | null;
  destinationMac: string | null;
  sourceIp: string | null;
  destinationIp: string | null;
  sourcePort: number | null;
  destinationPort: number | null;
  networkProtocol: string;
  transportProtocol: string | null;
  applicationProtocol: string | null;
  tcpFlags: string[] | null;
  ttl: number | null;
  payloadLength: number;
  info: string;
  issues: string[];
}

export interface PacketField {
  name: string;
  value: string;
  /** Byte offset of the field within the frame, when it maps to wire bytes. */
  offset: number | null;
  length: number;
}

export interface PacketSection {
  id: "summary" | "frame" | "ethernet" | "network" | "transport" | "application" | "payload";
  title: string;
  offset: number | null;
  length: number;
  fields: PacketField[];
}

export interface PacketDetail {
  summary: PacketSummary;
  sections: PacketSection[];
  /** Captured bytes of the frame. */
  bytes: number[];
}

export interface FlowEndpoint {
  ip: string;
  port: number;
}

export type TcpState = "SYN_SENT" | "SYN_RECEIVED" | "ESTABLISHED" | "CLOSING" | "CLOSED" | "RESET";

/** One bidirectional conversation. A is the side that spoke first (usually the client). */
export interface FlowView {
  id: number;
  protocol: string;
  applicationProtocol: string | null;
  endpointA: FlowEndpoint;
  endpointB: FlowEndpoint;
  /** Microseconds since the Unix epoch. */
  startedAt: number;
  lastSeenAt: number;
  /** Microseconds. */
  duration: number;
  packetsAToB: number;
  packetsBToA: number;
  bytesAToB: number;
  bytesBToA: number;
  totalPackets: number;
  totalBytes: number;
  tcpState: TcpState | null;
  retransmissions: number;
  resets: number;
  duplicateAcks: number;
  zeroWindows: number;
  /** TCP handshake round trip in microseconds. */
  latency: number | null;
  domains: string[];
  process: string | null;
  tls: TlsInfo | null;
  /** Bytes per second for the last 60 seconds. */
  sparkline: number[];
}

export type DnsStatus = "pending" | "ok" | "failed" | "timeout";

export interface DnsAnswer {
  name: string;
  recordType: string;
  data: string;
  ttl: number;
}

export interface DnsTransaction {
  id: number;
  flowId: number | null;
  client: string;
  resolver: string;
  transactionId: number;
  queryName: string;
  queryType: string;
  queryAt: number | null;
  responseAt: number | null;
  /** Microseconds. */
  latency: number | null;
  responseCode: string | null;
  status: DnsStatus;
  answers: DnsAnswer[];
}

export interface ResolverStat {
  ip: string;
  queries: number;
  failures: number;
  avgLatency: number | null;
}

export interface DnsStats {
  queries: number;
  responses: number;
  failures: number;
  uniqueDomains: number;
  avgLatency: number | null;
  p95Latency: number | null;
  resolvers: ResolverStat[];
}

export interface DnsPayload {
  transactions: DnsTransaction[];
  stats: DnsStats | null;
}

export interface CertMeta {
  subjectCn: string | null;
  subjectOrg: string | null;
  issuerCn: string | null;
  issuerOrg: string | null;
  notBefore: string | null;
  notAfter: string | null;
  dnsNames: string[];
}

/** TLS metadata read from the handshake. A null field means it was not observable. */
export interface TlsInfo {
  version: string | null;
  sni: string | null;
  alpnOffered: string[];
  alpnSelected: string | null;
  cipherSuite: string | null;
  certificate: CertMeta | null;
  clientHelloAt: number | null;
  serverHelloAt: number | null;
  handshakeEncrypted: boolean;
}

export type EventKind =
  | "dnsQuery"
  | "dnsResponse"
  | "dnsFailure"
  | "tcpConnect"
  | "tlsHandshake"
  | "flowStarted"
  | "flowEnded"
  | "retransmission"
  | "reset"
  | "latencySpike"
  | "trafficBurst";

export interface TimelineEvent {
  id: number;
  /** Microseconds since the Unix epoch (capture clock). */
  ts: number;
  kind: EventKind;
  flowId: number | null;
  host: string | null;
  domain: string | null;
  title: string;
  detail: string | null;
}

export interface MetricBucket {
  /** Unix second. */
  sec: number;
  packets: number;
  bytes: number;
  newFlows: number;
  activeFlows: number;
  retransmissions: number;
  resets: number;
  duplicateAcks: number;
  zeroWindows: number;
}

export interface TcpTotals {
  packets: number;
  retransmissions: number;
  resets: number;
  duplicateAcks: number;
  zeroWindows: number;
}

export interface RankEntry {
  key: string;
  bytes: number;
  packets: number;
  flows: number;
}

export interface Rankings {
  hosts: RankEntry[];
  domains: RankEntry[];
  protocols: RankEntry[];
  ports: RankEntry[];
  talkers: RankEntry[];
}

export type ProblemLabel = "potentialIssue" | "unusual" | "worthInvestigating";

export interface Problem {
  id: string;
  label: ProblemLabel;
  title: string;
  detail: string;
}

export interface AnalyticsSnapshot {
  series: MetricBucket[];
  tcp: TcpTotals;
  dns: DnsStats;
  rankings: Rankings;
  problems: Problem[];
}
