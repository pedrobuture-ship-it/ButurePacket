import { beforeEach, describe, expect, it } from "vitest";
import { filteredIndices, invalidatePacketView, makePacketView } from "./packetView";
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
});
