import { describe, expect, it } from "vitest";
import { DnsSubject, EventSubject, FlowSubject, PacketSubject } from "./adapters";
import { evaluate, parseFilter } from "./index";
import { makeFlow } from "@/features/flows/testFlow";
import type { PacketSummary } from "@/types/ipc";

const packet = (over: Partial<PacketSummary> = {}): PacketSummary => ({
  id: 1,
  flowId: 7,
  timestamp: 0,
  capturedLength: 1500,
  originalLength: 1500,
  sourceMac: "aa:bb:cc:dd:ee:ff",
  destinationMac: "11:22:33:44:55:66",
  sourceIp: "192.168.1.20",
  destinationIp: "140.82.121.4",
  sourcePort: 53214,
  destinationPort: 443,
  networkProtocol: "IPv4",
  transportProtocol: "TCP",
  applicationProtocol: "TLS",
  tcpFlags: ["SYN", "ACK"],
  ttl: 64,
  payloadLength: 0,
  info: "Client Hello",
  domain: null,
  latency: null,
  issues: [],
  ...over,
});

const matches = (filter: string, subject: { item: unknown } & Parameters<typeof evaluate>[1]) => {
  const r = parseFilter(filter);
  if (!r.ok) throw r.error;
  return evaluate(r.ast, subject);
};

describe("packet filtering", () => {
  const flow = makeFlow({ id: 7, latency: 21_000, tcpState: "ESTABLISHED", domains: ["api.github.com"], tls: { version: "TLS 1.3", sni: "github.com", alpnOffered: [], alpnSelected: null, cipherSuite: null, certificate: null, clientHelloAt: 1, serverHelloAt: 2, handshakeEncrypted: true } });
  const s = new PacketSubject((id) => (id === 7 ? flow : undefined));

  it("matches protocols across layers", () => {
    s.item = packet();
    for (const f of ["tcp", "tls", "ip", "ipv4", "protocol = tcp"]) expect(matches(f, s), f).toBe(true);
    for (const f of ["udp", "dns", "ipv6"]) expect(matches(f, s), f).toBe(false);
  });
  it("matches addresses, ports and flags", () => {
    s.item = packet();
    expect(matches("ip = 192.168.1.20 && dst.port = 443", s)).toBe(true);
    expect(matches("flags contains syn", s)).toBe(true);
    expect(matches("length > 1KB", s)).toBe(true);
    expect(matches("ttl = 64", s)).toBe(true);
  });
  it("resolves domain and latency through the flow when the packet has none", () => {
    s.item = packet();
    expect(matches('domain contains "github"', s)).toBe(true);
    expect(matches("sni = github.com", s)).toBe(true);
    expect(matches("latency > 20ms", s)).toBe(true);
    expect(matches("state = established", s)).toBe(true);
    s.item = packet({ domain: "other.example", latency: 5_000 });
    expect(matches("domain = other.example", s)).toBe(true);
    expect(matches("latency > 20ms", s)).toBe(false); // the packet's own latency wins
  });
  it("copes with packets that have no flow or no IP layer", () => {
    s.item = packet({ flowId: null, sourceIp: null, destinationIp: null, sourcePort: null, destinationPort: null, networkProtocol: "ARP", transportProtocol: null, applicationProtocol: null, tcpFlags: null, ttl: null });
    expect(matches("arp", s)).toBe(true);
    expect(matches("ip = 1.2.3.4", s)).toBe(false);
    expect(matches("ip != 1.2.3.4", s)).toBe(true);
    expect(matches("domain contains x", s)).toBe(false);
    expect(matches("tcp", s)).toBe(false);
  });
  it("reuses one subject across rows", () => {
    const rows = [packet({ id: 1 }), packet({ id: 2, sourcePort: 80, destinationPort: 8080, applicationProtocol: "HTTP" })];
    const r = parseFilter("http");
    if (!r.ok) throw r.error;
    expect(rows.filter((row) => ((s.item = row), evaluate(r.ast, s))).map((x) => x.id)).toEqual([2]);
  });
});

describe("flow / dns / event filtering", () => {
  it("filters flows by size, duration and endpoints", () => {
    const s = new FlowSubject();
    s.item = makeFlow({ totalBytes: 5 * 1024 * 1024, duration: 8_400_000, latency: 21_000, endpointB: { ip: "140.82.121.4", port: 443 }, protocol: "TCP", applicationProtocol: "TLS" });
    expect(matches("bytes > 1MB && dst.port = 443", s)).toBe(true);
    expect(matches("duration > 10s", s)).toBe(false);
    expect(matches("duration > 8s && latency < 50ms", s)).toBe(true);
    expect(matches("tls && ip = 140.82.0.0/16", s)).toBe(true);
    expect(matches("udp", s)).toBe(false);
  });
  it("filters DNS transactions", () => {
    const s = new DnsSubject();
    s.item = { id: 1, flowId: null, client: "192.168.1.20", resolver: "8.8.8.8", transactionId: 1, queryName: "api.github.com", queryType: "AAAA", queryAt: 1, responseAt: 2, latency: 80_000, responseCode: "NXDOMAIN", status: "failed", answers: [] };
    expect(matches("dns && latency > 50ms", s)).toBe(true);
    expect(matches("rcode = nxdomain", s)).toBe(true);
    expect(matches("type = aaaa && resolver = 8.8.8.8", s)).toBe(true);
    expect(matches("status = ok", s)).toBe(false);
    expect(matches("tcp", s)).toBe(false);
  });
  it("filters timeline events", () => {
    const s = new EventSubject();
    s.item = { id: 1, ts: 0, kind: "retransmission", flowId: 3, host: "140.82.121.4", domain: "github.com", title: "TCP retransmission", detail: "to 140.82.121.4:443" };
    expect(matches("flow = 3 && domain contains git", s)).toBe(true);
    expect(matches("type = retransmission", s)).toBe(true);
    expect(matches("tcp", s)).toBe(true);
    expect(matches("dns", s)).toBe(false);
    expect(matches('info contains "443"', s)).toBe(true);
  });
});
