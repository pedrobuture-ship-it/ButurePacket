import { beforeEach, describe, expect, it } from "vitest";
import { packetBuffer, usePacketsStore } from "./packets";
import type { PacketSummary } from "@/types/ipc";

const row = (id: number): PacketSummary => ({
  id,
  flowId: null,
  timestamp: id,
  capturedLength: 60,
  originalLength: 60,
  sourceMac: null,
  destinationMac: null,
  sourceIp: null,
  destinationIp: null,
  sourcePort: null,
  destinationPort: null,
  networkProtocol: "IPv4",
  transportProtocol: null,
  applicationProtocol: null,
  tcpFlags: null,
  ttl: null,
  payloadLength: 0,
  info: "",
  domain: null,
  latency: null,
  issues: [],
});

describe("packets store", () => {
  beforeEach(() => usePacketsStore.getState().clear());

  it("appends in place and publishes the count", async () => {
    usePacketsStore.getState().append([row(1), row(2)]);
    usePacketsStore.getState().append([row(3)]);
    await new Promise((r) => setTimeout(r, 0));
    expect(usePacketsStore.getState().count).toBe(3);
    expect(packetBuffer.get(2)?.id).toBe(3);
  });

  it("finds rows by id with binary search", () => {
    usePacketsStore.getState().append([1, 2, 5, 9].map(row));
    expect(packetBuffer.indexOfId(5)).toBe(2);
    expect(packetBuffer.indexOfId(4)).toBe(-1);
  });

  it("clear resets rows and selection", () => {
    usePacketsStore.getState().append([row(1)]);
    usePacketsStore.getState().select(1);
    usePacketsStore.getState().clear();
    expect(packetBuffer.rows).toHaveLength(0);
    expect(usePacketsStore.getState().selectedId).toBeNull();
  });
});
