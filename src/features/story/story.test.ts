import { describe, expect, it } from "vitest";
import { buildStory, countWord, findDnsLookup, formatSpanLong, storyToText } from "./story";
import { makeFlow } from "@/features/flows/testFlow";
import type { DnsTransaction, TimelineEvent } from "@/types/ipc";

const dns = (over: Partial<DnsTransaction> = {}): DnsTransaction => ({
  id: 1,
  flowId: null,
  client: "192.168.1.20",
  resolver: "8.8.8.8",
  transactionId: 1,
  queryName: "api.github.com",
  queryType: "A",
  queryAt: 1_000,
  responseAt: 22_000,
  latency: 21_000,
  responseCode: "NOERROR",
  status: "ok",
  answers: [{ name: "api.github.com", recordType: "A", data: "140.82.121.5", ttl: 60 }],
  ...over,
});

const flow = (over = {}) =>
  makeFlow({
    endpointA: { ip: "192.168.1.20", port: 53214 },
    endpointB: { ip: "140.82.121.5", port: 443 },
    startedAt: 50_000,
    duration: 8_400_000,
    bytesBToA: 18.2 * 1024 * 1024,
    bytesAToB: 1.3 * 1024 * 1024,
    retransmissions: 3,
    latency: 21_000,
    tcpState: "CLOSED",
    tls: { version: "TLS 1.3", sni: "api.github.com", alpnOffered: ["h2"], alpnSelected: null, cipherSuite: null, certificate: null, clientHelloAt: 1, serverHelloAt: 2, handshakeEncrypted: true },
    ...over,
  });

const connect: TimelineEvent = { id: 1, ts: 1, kind: "tcpConnect", flowId: 1, host: null, domain: null, title: "", detail: null };

describe("formatting helpers", () => {
  it("spells small counts and formats long spans", () => {
    expect(countWord(3)).toBe("three");
    expect(countWord(11)).toBe("11");
    expect(formatSpanLong(8_400_000)).toBe("8.4 seconds");
    expect(formatSpanLong(1_000_000)).toBe("1 second");
    expect(formatSpanLong(125_000_000)).toBe("2 minutes 5 seconds");
    expect(formatSpanLong(3_700_000_000)).toBe("1 hour 1 minute");
  });
});

describe("findDnsLookup", () => {
  it("matches client, address and ordering; picks the most recent", () => {
    const f = flow();
    expect(findDnsLookup(f, [dns()])?.id).toBe(1);
    expect(findDnsLookup(f, [dns({ id: 1 }), dns({ id: 2, responseAt: 30_000 })])?.id).toBe(2);
    expect(findDnsLookup(f, [dns({ client: "10.0.0.9" })])).toBeNull();
    expect(findDnsLookup(f, [dns({ responseAt: 99_000 })])).toBeNull(); // answered after the flow began
    expect(findDnsLookup(f, [dns({ status: "failed" })])).toBeNull();
    expect(findDnsLookup(f, [dns({ answers: [{ name: "x", recordType: "A", data: "1.2.3.4", ttl: 1 }] })])).toBeNull();
  });
});

describe("buildStory", () => {
  it("tells the connection story in order using only observed facts", () => {
    const s = buildStory(flow(), [connect], [dns()]);
    expect(s.observed.map((o) => o.text)).toEqual([
      "Your device queried api.github.com using DNS (A record, via 8.8.8.8).",
      "DNS responded after 21 ms.",
      "The DNS answer included 140.82.121.5, the address this connection went to.",
      "A TCP connection was opened to 140.82.121.5:443 (handshake took 21 ms).",
      "The client asked for the server name api.github.com (TLS SNI).",
      "TLS 1.3 was negotiated.",
      "Certificate details are encrypted in TLS 1.3 and cannot be shown.",
      "The connection remained active for 8.4 seconds.",
      "18.2 MB were received.",
      "1.3 MB were sent.",
      "Three retransmissions were observed.",
      "The connection closed normally.",
    ]);
  });

  it("keeps interpretations separate and always explains them", () => {
    const s = buildStory(flow(), [connect], [dns()]);
    expect(s.inferred.length).toBeGreaterThan(0);
    expect(s.inferred.every((i) => i.basis && i.basis.length > 10)).toBe(true);
    expect(s.inferred.some((i) => i.text.includes("probably made to api.github.com"))).toBe(true);
    // hedged language, no facts smuggled in
    expect(s.inferred.some((i) => /may have been lost/.test(i.text))).toBe(true);
    expect(s.observed.some((o) => /probably|likely|may/.test(o.text))).toBe(false);
  });

  it("does not claim a DNS lookup or handshake that was not captured", () => {
    const s = buildStory(flow({ domains: ["api.github.com"], latency: null, tls: null, retransmissions: 0, tcpState: "ESTABLISHED" }), [], []);
    const text = s.observed.map((o) => o.text).join(" ");
    expect(text).not.toMatch(/queried/);
    expect(text).toMatch(/already in progress/);
    expect(text).toMatch(/still open/);
    expect(s.inferred[0].text).toBe("The destination is likely api.github.com.");
  });

  it("describes resets and non-TCP flows", () => {
    const s = buildStory(flow({ resets: 1, tcpState: "RESET", tls: null, retransmissions: 0 }), [connect], []);
    expect(s.observed.at(-1)?.text).toBe("The connection was ended with a reset (RST).");
    expect(s.inferred.some((i) => /refused or abandoned/.test(i.text))).toBe(true);
    const u = buildStory(makeFlow({ protocol: "UDP", endpointB: { ip: "8.8.8.8", port: 53 }, tcpState: null, tls: null, duration: 1_000_000 }), [], []);
    expect(u.observed[0].text).toBe("UDP packets were exchanged with 8.8.8.8:53.");
    expect(u.observed.some((o) => /still open|closed/.test(o.text))).toBe(false);
  });

  it("uses singular grammar and renders plain text", () => {
    const s = buildStory(flow({ retransmissions: 1 }), [connect], [dns()]);
    expect(s.observed.map((o) => o.text)).toContain("One retransmission was observed.");
    const text = storyToText(s);
    expect(text.startsWith("Observed\n1. ")).toBe(true);
    expect(text).toContain("Inferred (not directly observed)");
  });
});
