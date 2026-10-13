import { describe, expect, it } from "vitest";
import { distribution, pickStoryFlow, topConnections, uniqueDomains } from "./model";
import { makeFlow } from "@/features/flows/testFlow";

const r = (key: string, bytes: number) => ({ key, bytes, packets: 0, flows: 0 });

describe("distribution", () => {
  it("computes fractions and folds the tail into Other", () => {
    const d = distribution([r("TLS", 600), r("DNS", 200), r("QUIC", 100), r("HTTP", 50), r("SSH", 30), r("NTP", 15), r("DHCP", 5)], 5);
    expect(d.map((s) => s.key)).toEqual(["TLS", "DNS", "QUIC", "HTTP", "SSH", "Other"]);
    expect(d[0].fraction).toBeCloseTo(0.6);
    expect(d.at(-1)).toMatchObject({ bytes: 20 });
    expect(d.reduce((s, x) => s + x.fraction, 0)).toBeCloseTo(1);
  });
  it("has no slices without traffic and no Other when everything fits", () => {
    expect(distribution([])).toEqual([]);
    expect(distribution([r("A", 0)])).toEqual([]);
    expect(distribution([r("A", 5), r("B", 5)]).map((s) => s.key)).toEqual(["A", "B"]);
  });
});

describe("topConnections", () => {
  it("orders by traffic and limits", () => {
    const flows = [makeFlow({ id: 1, totalBytes: 5 }), makeFlow({ id: 2, totalBytes: 50 }), makeFlow({ id: 3, totalBytes: 50 }), makeFlow({ id: 4, totalBytes: 10 })];
    expect(topConnections(flows, 3).map((f) => f.id)).toEqual([2, 3, 4]);
  });
});

describe("pickStoryFlow", () => {
  const tls = { version: "TLS 1.3", sni: "x.com", alpnOffered: [], alpnSelected: null, cipherSuite: null, certificate: null, clientHelloAt: 1, serverHelloAt: 2, handshakeEncrypted: true };
  it("prefers recent flows that have something to tell", () => {
    const flows = [makeFlow({ id: 1, lastSeenAt: 100, totalBytes: 5000 }), makeFlow({ id: 2, lastSeenAt: 50, totalBytes: 5000, tls }), makeFlow({ id: 3, lastSeenAt: 200, totalBytes: 10 })];
    expect(pickStoryFlow(flows)?.id).toBe(2);
  });
  it("falls back to the most recent flow, or null", () => {
    expect(pickStoryFlow([makeFlow({ id: 1, lastSeenAt: 1 }), makeFlow({ id: 2, lastSeenAt: 9 })])?.id).toBe(2);
    expect(pickStoryFlow([])).toBeNull();
  });
  it("counts retransmissions as interesting", () => {
    expect(pickStoryFlow([makeFlow({ id: 1, lastSeenAt: 10, totalBytes: 5000, retransmissions: 2 }), makeFlow({ id: 2, lastSeenAt: 20, totalBytes: 5000 })])?.id).toBe(1);
  });
});

describe("uniqueDomains", () => {
  it("counts distinct names across SNI and DNS hints, case-insensitively", () => {
    const tls = { version: null, sni: "GitHub.com", alpnOffered: [], alpnSelected: null, cipherSuite: null, certificate: null, clientHelloAt: null, serverHelloAt: null, handshakeEncrypted: false };
    expect(uniqueDomains([makeFlow({ tls, domains: ["github.com", "api.github.com"] }), makeFlow({ domains: ["API.github.com"] })])).toBe(2);
    expect(uniqueDomains([])).toBe(0);
  });
});
