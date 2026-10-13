import { describe, expect, it } from "vitest";
import { endpointText, flowProblems, flowProtocolLabel, tlsSummary } from "./flowText";
import { makeFlow } from "./testFlow";

describe("flow text helpers", () => {
  it("formats endpoints, bracketing IPv6 when a port is shown", () => {
    expect(endpointText({ ip: "10.0.0.1", port: 443 })).toBe("10.0.0.1");
    expect(endpointText({ ip: "10.0.0.1", port: 443 }, true)).toBe("10.0.0.1:443");
    expect(endpointText({ ip: "fe80::1", port: 53 }, true)).toBe("[fe80::1]:53");
    expect(endpointText({ ip: "10.0.0.1", port: 0 }, true)).toBe("10.0.0.1");
  });
  it("prefers the application protocol", () => {
    expect(flowProtocolLabel(makeFlow({ applicationProtocol: "DNS", protocol: "UDP" }))).toBe("DNS");
    expect(flowProtocolLabel(makeFlow({ applicationProtocol: null, protocol: "UDP" }))).toBe("UDP");
  });
  it("lists problems with careful wording", () => {
    expect(flowProblems(makeFlow())).toEqual([]);
    const p = flowProblems(makeFlow({ retransmissions: 3, resets: 1, duplicateAcks: 4, zeroWindows: 1, latency: 300_000 }));
    expect(p).toHaveLength(5);
    expect(p[0]).toBe("3 TCP retransmissions observed");
    expect(flowProblems(makeFlow({ retransmissions: 1 }))[0]).toBe("1 TCP retransmission observed");
  });

  it("summarises TLS and never invents missing data", () => {
    expect(tlsSummary(makeFlow())).toEqual([]);
    const base = { version: "TLS 1.3", sni: "github.com", alpnOffered: ["h2", "http/1.1"], alpnSelected: null, cipherSuite: null, certificate: null, clientHelloAt: 1, serverHelloAt: 2, handshakeEncrypted: true };
    expect(tlsSummary(makeFlow({ tls: { ...base, alpnSelected: "h2" } }))).toEqual(["TLS 1.3", "SNI: github.com", "ALPN: h2"]);
    expect(tlsSummary(makeFlow({ tls: base }))[2]).toBe("ALPN: h2, http/1.1 (offered)");
    expect(tlsSummary(makeFlow({ tls: { ...base, version: null, sni: null, alpnOffered: [] } }))).toEqual(["Unavailable", "SNI: Unavailable", "ALPN: Unavailable"]);
  });
});
