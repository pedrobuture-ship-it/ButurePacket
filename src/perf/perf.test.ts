/**
 * Frontend performance probes. Skipped in normal runs; execute with `npm run perf`.
 * They print timings instead of asserting hard limits (CI machines vary), but each has a loose
 * ceiling so a gross regression still fails.
 */
import { describe, expect, it } from "vitest";
import { filteredIndices, invalidatePacketView } from "@/features/packets/packetView";
import { makeFlow } from "@/features/flows/testFlow";
import { sortFlows } from "@/features/flows/sort";
import { buildGraph, DEFAULT_OPTIONS } from "@/features/topology/graph";
import { FlowSubject } from "@/lib/filter/adapters";
import { filterItems } from "@/lib/filter/apply";
import { parseFilter } from "@/lib/filter";
import { packetBuffer, usePacketsStore } from "@/stores/packets";
import type { PacketSummary, TimelineEvent } from "@/types/ipc";

const run = process.env.PERF ? describe : describe.skip;
// stderr bypasses the test reporter's console capture
const out = (line: string) => process.stderr.write(line + "\n");

const row = (i: number): PacketSummary => ({
  id: i,
  flowId: i % 800,
  timestamp: 1_700_000_000_000_000 + i * 100,
  capturedLength: 1454,
  originalLength: 1454,
  sourceMac: "02:00:00:00:00:01",
  destinationMac: "02:00:00:00:00:02",
  sourceIp: `140.82.${i % 250}.${(i * 7) % 250}`,
  destinationIp: "192.168.1.20",
  sourcePort: 443,
  destinationPort: 40000 + (i % 800),
  networkProtocol: "IPv4",
  transportProtocol: i % 5 ? "TCP" : "UDP",
  applicationProtocol: i % 5 ? "TLS" : "DNS",
  tcpFlags: ["ACK"],
  ttl: 64,
  payloadLength: 1400,
  info: `443 → ${40000 + (i % 800)} [ACK] Seq=${i * 1400} Win=64240 Len=1400 Ack=${i * 3}`,
  domain: null,
  latency: null,
  issues: [],
});

const time = <T>(label: string, fn: () => T): { value: T; ms: number } => {
  const t = performance.now();
  const value = fn();
  const ms = performance.now() - t;
  out(`  ${label.padEnd(46)} ${ms.toFixed(1).padStart(9)} ms`);
  return { value, ms };
};

run("frontend performance", () => {
  it.each([20_000, 100_000, 500_000, 1_000_000])("ingest %i packet rows (JSON.parse + append)", (n) => {
    usePacketsStore.getState().clear();
    const batches = Array.from({ length: n / 5000 }, (_, b) => JSON.stringify(Array.from({ length: 5000 }, (_, i) => row(b * 5000 + i + 1))));
    const { ms } = time(`parse+append ${n.toLocaleString()} rows`, () => {
      for (const json of batches) usePacketsStore.getState().append(JSON.parse(json) as PacketSummary[]);
    });
    out(`    → ${(n / (ms / 1000) / 1000).toFixed(0)}k rows/s`);
    expect(packetBuffer.rows.length).toBe(Math.min(n, 1_000_000));
    expect(ms).toBeLessThan(n / 20); // at least 20k rows/s
  });

  it("filters 1M rows, then extends the filter incrementally", () => {
    usePacketsStore.getState().clear();
    invalidatePacketView();
    const all = Array.from({ length: 1_000_000 }, (_, i) => row(i + 1));
    usePacketsStore.getState().append(all);
    const r = parseFilter("tcp && dst.port > 40100 && ip = 192.168.1.0/24");
    if (!r.ok) throw r.error;
    const first = time("evaluate `tcp && dst.port > … && ip = CIDR` on 1M rows", () => filteredIndices(r.ast, packetBuffer.rows.length));
    expect(first.value?.length).toBeGreaterThan(0);
    usePacketsStore.getState().append(Array.from({ length: 5000 }, (_, i) => row(1_000_001 + i)));
    const inc = time("…then 5,000 new rows (incremental)", () => filteredIndices(r.ast, packetBuffer.rows.length));
    expect(inc.ms).toBeLessThan(first.ms / 10);
  });

  it("sorts and filters 100k flows", () => {
    const flows = Array.from({ length: 100_000 }, (_, i) => makeFlow({ id: i + 1, totalBytes: (i * 2654435761) % 1_000_000_000, duration: i % 9999, latency: i % 7 ? i : null, lastSeenAt: i }));
    const sorted = time("sort 100k flows by traffic", () => sortFlows(flows, "traffic"));
    expect(sorted.value[0].totalBytes).toBeGreaterThanOrEqual(sorted.value[1].totalBytes);
    const f = parseFilter("tcp && bytes > 10MB");
    if (!f.ok) throw f.error;
    time("filter 100k flows (`tcp && bytes > 10MB`)", () => filterItems(flows, f.ast, new FlowSubject()));
    expect(sorted.ms).toBeLessThan(2000);
  });

  it("builds the network graph from 20k flows", () => {
    const flows = Array.from({ length: 20_000 }, (_, i) => makeFlow({ id: i + 1, endpointB: { ip: `30.${(i >> 8) & 255}.${i & 255}.1`, port: 443 }, totalBytes: i * 1000 }));
    const g = time("buildGraph (20k flows → ≤150 nodes + clusters)", () => buildGraph(flows, { ...DEFAULT_OPTIONS, localIps: new Set(["192.168.1.20"]) }));
    expect(g.value.nodes.length).toBeLessThan(400);
    expect(g.ms).toBeLessThan(1500);
  });

  it("orders 300k timeline events", () => {
    const events: TimelineEvent[] = Array.from({ length: 300_000 }, (_, i) => ({ id: i, ts: i * 10 + (i % 3), kind: "flowStarted", flowId: i % 1000, host: null, domain: null, title: "x", detail: null }));
    const t = time("sort 300k events (nearly sorted)", () => [...events].sort((a, b) => a.ts - b.ts || a.id - b.id));
    expect(t.ms).toBeLessThan(2000);
  });
});
