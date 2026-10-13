import { beforeEach, describe, expect, it } from "vitest";
import { filterProgress, filteredIndices, invalidatePacketView, makePacketView, makeStoredView } from "./packetView";
import { packetBuffer, usePacketsStore } from "@/stores/packets";
import { parseFilter } from "@/lib/filter";
import type { PacketSummary } from "@/types/ipc";

const row = (id: number, port: number): PacketSummary => ({
  id, flowId: null, timestamp: id, capturedLength: 60, originalLength: 60, sourceMac: null, destinationMac: null, sourceIp: "10.0.0.1", destinationIp: "10.0.0.2", sourcePort: 1000, destinationPort: port,
  networkProtocol: "IPv4", transportProtocol: "TCP", applicationProtocol: null, tcpFlags: null, ttl: 64, payloadLength: 0, info: "", domain: null, latency: null, issues: [],
});
const ast = (t: string) => {
  const r = parseFilter(t);
  if (!r.ok) throw r.error;
  return r.ast;
};

describe("packet view", () => {
  beforeEach(() => {
    usePacketsStore.getState().clear();
    invalidatePacketView();
  });

  it("returns null (identity) without a filter", () => {
    usePacketsStore.getState().append([row(1, 80)]);
    expect(filteredIndices(null, 1)).toBeNull();
    const v = makePacketView(null, 1);
    expect(v.count).toBe(1);
    expect(v.positionOfId(1)).toBe(0);
  });

  it("filters incrementally and keeps earlier results", () => {
    const f = ast("dst.port = 443");
    usePacketsStore.getState().append([row(1, 443), row(2, 80), row(3, 443)]);
    expect(filteredIndices(f, 3)).toEqual([0, 2]);
    usePacketsStore.getState().append([row(4, 443), row(5, 22)]);
    expect(filteredIndices(f, 5)).toEqual([0, 2, 3]);
  });

  it("re-evaluates when the filter changes or the buffer shrinks", () => {
    usePacketsStore.getState().append([row(1, 443), row(2, 80)]);
    expect(filteredIndices(ast("dst.port = 443"), 2)).toEqual([0]);
    expect(filteredIndices(ast("dst.port = 80"), 2)).toEqual([1]);
    usePacketsStore.getState().clear();
    usePacketsStore.getState().append([row(1, 80)]);
    expect(filteredIndices(ast("dst.port = 80"), 1)).toEqual([0]);
  });

  it("maps ids to positions inside the filtered view", () => {
    usePacketsStore.getState().append([row(10, 443), row(11, 80), row(12, 443), row(13, 443)]);
    const idx = filteredIndices(ast("dst.port = 443"), 4)!;
    const v = makePacketView(idx, 4);
    expect(v.count).toBe(3);
    expect(v.at(1)?.id).toBe(12);
    expect(v.positionOfId(13)).toBe(2);
    expect(v.positionOfId(11)).toBe(-1); // filtered out
    expect(v.positionOfId(999)).toBe(-1);
    expect(v.at(99)).toBeUndefined();
    expect(packetBuffer.rows).toHaveLength(4);
  });

  it("can work in time slices and resume where it stopped", () => {
    usePacketsStore.getState().append(Array.from({ length: 50_000 }, (_, i) => row(i + 1, i % 2 ? 443 : 80)));
    const f = ast("dst.port = 443");
    let p = filterProgress(f, 50_000, 0); // zero budget: one 2,048-row slice at a time
    expect(p.done).toBe(false);
    expect(p.processed).toBeGreaterThan(0);
    expect(p.processed).toBeLessThanOrEqual(2048);
    let guard = 0;
    while (!p.done && guard++ < 100) p = filterProgress(f, 50_000, 0);
    expect(p.done).toBe(true);
    expect(p.indices).toHaveLength(25_000);
    expect(p.indices?.[0]).toBe(1);
    expect(filterProgress(null, 50_000).indices).toBeNull();
  });

  it("restarts when rows were trimmed from the front", () => {
    usePacketsStore.getState().append([row(1, 443), row(2, 443)]);
    const f = ast("dst.port = 443");
    expect(filteredIndices(f, 2)).toEqual([0, 1]);
    packetBuffer.rows.splice(0, 1);
    packetBuffer.generation++;
    expect(filteredIndices(f, 1)).toEqual([0]);
  });

  it("builds a view over stored rows", () => {
    const rows = [row(10, 443), row(20, 80), row(35, 443)];
    const v = makeStoredView(rows);
    expect(v.count).toBe(3);
    expect(v.at(1)?.id).toBe(20);
    expect(v.at(9)).toBeUndefined();
    expect(v.positionOfId(35)).toBe(2);
    expect(v.positionOfId(11)).toBe(-1);
    expect(makeStoredView([]).positionOfId(1)).toBe(-1);
  });
});
