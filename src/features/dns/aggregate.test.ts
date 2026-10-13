import { describe, expect, it } from "vitest";
import { aggregateDomains, answersText } from "./aggregate";
import type { DnsTransaction } from "@/types/ipc";

const tx = (over: Partial<DnsTransaction>): DnsTransaction => ({
  id: 1,
  flowId: null,
  client: "192.168.1.20",
  resolver: "8.8.8.8",
  transactionId: 1,
  queryName: "api.github.com",
  queryType: "A",
  queryAt: 100,
  responseAt: 120,
  latency: 20_000,
  responseCode: "NOERROR",
  status: "ok",
  answers: [{ name: "api.github.com", recordType: "A", data: "140.82.121.5", ttl: 60 }],
  ...over,
});

describe("aggregateDomains", () => {
  it("groups case-insensitively and averages latency", () => {
    const rows = aggregateDomains([tx({ id: 1 }), tx({ id: 2, queryName: "API.GitHub.com", latency: 40_000, queryAt: 200 })]);
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({ domain: "api.github.com", queries: 2, avgLatency: 30_000, lastSeen: 200 });
  });
  it("counts failures and timeouts but ignores missing latencies", () => {
    const rows = aggregateDomains([tx({ status: "failed", latency: null, answers: [] }), tx({ id: 2, status: "timeout", latency: null, answers: [] })]);
    expect(rows[0].failures).toBe(2);
    expect(rows[0].avgLatency).toBeNull();
  });
  it("collects each address once and does not assume exclusivity", () => {
    const rows = aggregateDomains([
      tx({ id: 1 }),
      tx({ id: 2, answers: [{ name: "x", recordType: "A", data: "140.82.121.5", ttl: 1 }, { name: "x", recordType: "AAAA", data: "2606::1", ttl: 1 }, { name: "x", recordType: "CNAME", data: "lb.example", ttl: 1 }] }),
      tx({ id: 3, queryName: "uploads.github.com", queryAt: 50 }),
    ]);
    expect(rows.map((r) => r.domain)).toEqual(["api.github.com", "uploads.github.com"]);
    expect(rows[0].addresses).toEqual(["140.82.121.5", "2606::1"]);
    expect(rows[1].addresses).toEqual(["140.82.121.5"]); // same address, different domain
  });
});

describe("answersText", () => {
  it("skips CNAMEs and truncates long lists", () => {
    const answers = ["1.1.1.1", "2.2.2.2", "3.3.3.3", "4.4.4.4"].map((data) => ({ name: "n", recordType: "A", data, ttl: 1 }));
    expect(answersText(tx({ answers }))).toBe("1.1.1.1, 2.2.2.2, 3.3.3.3, …");
    expect(answersText(tx({ answers: [], status: "pending" }))).toBe("…");
    expect(answersText(tx({ answers: [], status: "failed" }))).toBe("—");
  });
});
