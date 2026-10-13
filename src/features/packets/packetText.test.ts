import { describe, expect, it } from "vitest";
import { endpoint, packetToText, protocolLabel } from "./packetText";
import type { PacketSummary } from "@/types/ipc";

const base: PacketSummary = {
  id: 1,
  flowId: 1,
  timestamp: new Date(2024, 0, 1, 10, 0, 0, 5).getTime() * 1000,
  capturedLength: 74,
  originalLength: 74,
  sourceMac: "aa:bb:cc:dd:ee:ff",
  destinationMac: "11:22:33:44:55:66",
  sourceIp: "192.168.1.20",
  destinationIp: "8.8.8.8",
  sourcePort: 55321,
  destinationPort: 53,
  networkProtocol: "IPv4",
  transportProtocol: "UDP",
  applicationProtocol: "DNS",
  tcpFlags: null,
  ttl: 64,
  payloadLength: 32,
  info: "55321 → 53 Len=32",
  issues: [],
};

describe("packet text helpers", () => {
  it("prefers application protocol, then transport, then network", () => {
    expect(protocolLabel(base)).toBe("DNS");
    expect(protocolLabel({ ...base, applicationProtocol: null })).toBe("UDP");
    expect(protocolLabel({ ...base, applicationProtocol: null, transportProtocol: null })).toBe("IPv4");
  });
  it("falls back to MAC then dash for endpoints", () => {
    expect(endpoint({ ...base, sourceIp: null }, "src")).toBe("aa:bb:cc:dd:ee:ff");
    expect(endpoint({ ...base, destinationIp: null, destinationMac: null }, "dst")).toBe("—");
  });
  it("serialises a row as TSV", () => {
    expect(packetToText(base).split("\t")).toEqual(["1", "10:00:00.005", "192.168.1.20", "8.8.8.8", "DNS", "55321", "53", "74", "55321 → 53 Len=32"]);
  });
});
