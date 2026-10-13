import type { FlowView } from "@/types/ipc";

/** Test helper: a plausible flow with selectively overridden fields. */
export function makeFlow(over: Partial<FlowView> = {}): FlowView {
  return {
    id: 1,
    protocol: "TCP",
    applicationProtocol: "TLS",
    endpointA: { ip: "192.168.1.20", port: 53214 },
    endpointB: { ip: "140.82.121.4", port: 443 },
    startedAt: 0,
    lastSeenAt: 0,
    duration: 0,
    packetsAToB: 0,
    packetsBToA: 0,
    bytesAToB: 0,
    bytesBToA: 0,
    totalPackets: 0,
    totalBytes: 0,
    tcpState: "ESTABLISHED",
    retransmissions: 0,
    resets: 0,
    duplicateAcks: 0,
    zeroWindows: 0,
    latency: null,
    domains: [],
    process: null,
    sparkline: new Array(60).fill(0),
    ...over,
  };
}
