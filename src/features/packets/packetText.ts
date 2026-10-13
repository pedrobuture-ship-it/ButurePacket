import type { PacketSummary } from "@/types/ipc";
import { formatTimestamp } from "@/lib/format";

export function endpoint(p: PacketSummary, side: "src" | "dst"): string {
  const ip = side === "src" ? p.sourceIp : p.destinationIp;
  const mac = side === "src" ? p.sourceMac : p.destinationMac;
  return ip ?? mac ?? "—";
}

export function protocolLabel(p: PacketSummary): string {
  return p.applicationProtocol ?? p.transportProtocol ?? p.networkProtocol;
}

/** Tab-separated line, ready to paste into a spreadsheet or chat. */
export function packetToText(p: PacketSummary): string {
  return [p.id, formatTimestamp(p.timestamp), endpoint(p, "src"), endpoint(p, "dst"), protocolLabel(p), p.sourcePort ?? "", p.destinationPort ?? "", p.capturedLength, p.info].join("\t");
}
