import { beforeEach, describe, expect, it, vi } from "vitest";
import { MAX_TRANSACTIONS, dnsBuffer, useDnsStore } from "./dns";
import type { DnsStats, DnsTransaction } from "@/types/ipc";

const tx = (id: number): DnsTransaction => ({ id, flowId: null, client: "c", resolver: "r", transactionId: id, queryName: `h${id}.example`, queryType: "A", queryAt: id, responseAt: null, latency: null, responseCode: null, status: "pending", answers: [] });
const stats = (queries: number): DnsStats => ({ queries, responses: 0, failures: 0, uniqueDomains: 0, avgLatency: null, p95Latency: null, resolvers: [] });

describe("dns store", () => {
  beforeEach(() => {
    vi.useFakeTimers();
    useDnsStore.getState().clear();
  });

  it("upserts transactions and publishes stats immediately but the version lazily", () => {
    const v0 = useDnsStore.getState().version;
    useDnsStore.getState().apply({ transactions: [tx(1), tx(2)], stats: stats(2) });
    useDnsStore.getState().apply({ transactions: [{ ...tx(1), status: "ok" }], stats: null });
    expect(useDnsStore.getState().stats.queries).toBe(2); // null stats keep the previous value
    expect(useDnsStore.getState().version).toBe(v0);
    vi.advanceTimersByTime(300);
    expect(useDnsStore.getState().version).toBe(v0 + 1);
    expect(dnsBuffer.byId.size).toBe(2);
    expect(dnsBuffer.byId.get(1)?.status).toBe("ok");
  });

  it("drops the oldest transactions beyond the cap", () => {
    useDnsStore.getState().apply({ transactions: Array.from({ length: MAX_TRANSACTIONS + 10 }, (_, i) => tx(i + 1)), stats: null });
    expect(dnsBuffer.byId.size).toBe(MAX_TRANSACTIONS);
    expect(dnsBuffer.byId.has(1)).toBe(false);
    expect(dnsBuffer.byId.has(MAX_TRANSACTIONS + 10)).toBe(true);
  });

  it("clear resets everything", () => {
    useDnsStore.getState().apply({ transactions: [tx(1)], stats: stats(1) });
    useDnsStore.getState().clear();
    expect(dnsBuffer.byId.size).toBe(0);
    expect(useDnsStore.getState().stats.queries).toBe(0);
  });
});
