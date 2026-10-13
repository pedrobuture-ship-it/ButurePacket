import type { FlowEndpoint, FlowView } from "@/types/ipc";

export function endpointText(e: FlowEndpoint, showPort = false): string {
  const host = e.ip.includes(":") ? `[${e.ip}]` : e.ip;
  return showPort && e.port > 0 ? `${host}:${e.port}` : e.ip;
}

export function flowProtocolLabel(f: FlowView): string {
  return f.applicationProtocol ?? f.protocol;
}

/** Heuristic problem list shown in the flow inspector; wording stays non-accusatory. */
export function flowProblems(f: FlowView): string[] {
  const out: string[] = [];
  if (f.retransmissions > 0) out.push(`${f.retransmissions} TCP retransmission${f.retransmissions === 1 ? "" : "s"} observed`);
  if (f.resets > 0) out.push(`Connection was reset (${f.resets} RST packet${f.resets === 1 ? "" : "s"})`);
  if (f.duplicateAcks >= 3) out.push(`${f.duplicateAcks} duplicate ACKs observed`);
  if (f.zeroWindows > 0) out.push(`Receiver advertised a zero window ${f.zeroWindows} time${f.zeroWindows === 1 ? "" : "s"}`);
  if (f.latency !== null && f.latency > 200_000) out.push("High handshake latency (over 200 ms)");
  return out;
}
