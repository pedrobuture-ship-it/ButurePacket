// Fills the UI stores with a realistic-looking capture (DNS lookup, TLS connections, a retransmission).
// Runs inside the page, so it imports the app's own store modules from the dev server.
export const SEED = `(async () => {
  const [pk, fl, dn, ev, an, cp, ui] = await Promise.all([
    import("/src/stores/packets.ts"), import("/src/stores/flows.ts"), import("/src/stores/dns.ts"), import("/src/stores/events.ts"),
    import("/src/stores/analytics.ts"), import("/src/stores/capture.ts"), import("/src/stores/ui.ts"),
  ]);
  const now = Date.now() * 1000;
  const t0 = now - 14 * 60 * 1e6;
  const CLIENT = "192.168.1.20";
  const servers = [
    ["140.82.121.4", "github.com", 18.4e6, "TLS"], ["151.101.65.194", "github.githubassets.com", 5.6e6, "TLS"], ["185.199.110.153", "raw.githubusercontent.com", 3.1e6, "TLS"],
    ["104.18.34.12", "cdn.example.net", 12.4e6, "TLS"], ["142.250.80.46", "www.google.com", 9.2e6, "QUIC"], ["8.8.8.8", null, 1.2e3, "DNS"], ["1.1.1.1", null, 1.1e3, "DNS"], ["192.168.1.1", null, 6.2e2, "DNS"],
  ];
  const flows = servers.map(([ip, dom, bytes, app], i) => ({
    id: i + 1, protocol: app === "DNS" || app === "QUIC" ? "UDP" : "TCP", applicationProtocol: app, endpointA: { ip: CLIENT, port: 53214 + i }, endpointB: { ip, port: app === "DNS" ? 53 : 443 },
    startedAt: t0 + i * 5e6, lastSeenAt: now - i * 3e5, duration: 8.4e6 + i * 6e6, packetsAToB: 900 + i * 37, packetsBToA: 12000 + i * 211, bytesAToB: bytes * 0.07, bytesBToA: bytes * 0.93,
    totalPackets: 12900 + i * 248, totalBytes: bytes, tcpState: app === "TLS" ? (i === 0 ? "CLOSED" : "ESTABLISHED") : null, retransmissions: i === 0 ? 3 : 0, resets: 0, duplicateAcks: 0, zeroWindows: 0,
    latency: 21000 + i * 3000, domains: i === 0 ? ["api.github.com"] : dom ? [dom] : [], process: null,
    tls: app === "TLS" ? { version: "TLS 1.3", sni: dom, alpnOffered: ["h2", "http/1.1"], alpnSelected: null, cipherSuite: "TLS_AES_128_GCM_SHA256", certificate: null, clientHelloAt: t0, serverHelloAt: t0 + 30000, handshakeEncrypted: true } : null,
  }));
  fl.useFlowsStore.getState().upsert(flows);
  fl.useFlowsStore.getState().select(1);

  const rows = [];
  const mk = (i, over) => ({ id: i, flowId: 1, timestamp: t0 + i * 10000, capturedLength: 74, originalLength: 74, sourceMac: "3c:fd:fe:12:34:56", destinationMac: "52:54:00:12:34:56", sourceIp: CLIENT, destinationIp: "140.82.121.4", sourcePort: 53214, destinationPort: 443, networkProtocol: "IPv4", transportProtocol: "TCP", applicationProtocol: "TLS", tcpFlags: ["ACK"], ttl: 64, payloadLength: 0, info: "", domain: null, latency: null, issues: [], ...over });
  rows.push(mk(1, { flowId: 6, destinationIp: "8.8.8.8", destinationPort: 53, sourcePort: 55321, transportProtocol: "UDP", applicationProtocol: "DNS", tcpFlags: null, capturedLength: 78, info: "Standard query A api.github.com", domain: "api.github.com" }));
  rows.push(mk(2, { flowId: 6, sourceIp: "8.8.8.8", destinationIp: CLIENT, sourcePort: 53, destinationPort: 55321, transportProtocol: "UDP", applicationProtocol: "DNS", tcpFlags: null, capturedLength: 124, info: "Standard query response A api.github.com 140.82.121.4", domain: "api.github.com", latency: 21000 }));
  rows.push(mk(3, { tcpFlags: ["SYN"], info: "53214 → 443 [SYN] Seq=0 Win=64240 Len=0 MSS=1460" }));
  rows.push(mk(4, { sourceIp: "140.82.121.4", destinationIp: CLIENT, sourcePort: 443, destinationPort: 53214, tcpFlags: ["SYN", "ACK"], info: "443 → 53214 [SYN, ACK] Seq=0 Ack=1 Win=65160 Len=0 MSS=1460" }));
  rows.push(mk(5, { info: "53214 → 443 [ACK] Seq=1 Ack=1 Win=64240 Len=0" }));
  rows.push(mk(6, { capturedLength: 517, payloadLength: 463, tcpFlags: ["PSH", "ACK"], info: "Client Hello (SNI: github.com)", domain: "github.com" }));
  rows.push(mk(7, { sourceIp: "140.82.121.4", destinationIp: CLIENT, sourcePort: 443, destinationPort: 53214, capturedLength: 1389, payloadLength: 1335, tcpFlags: ["ACK"], info: "Server Hello" }));
  rows.push(mk(8, { sourceIp: "140.82.121.4", destinationIp: CLIENT, sourcePort: 443, destinationPort: 53214, capturedLength: 312, payloadLength: 258, tcpFlags: ["PSH", "ACK"], info: "Change Cipher Spec, Application Data" }));
  for (let i = 9; i <= 60; i++) rows.push(mk(i, i % 3 ? { sourceIp: "140.82.121.4", destinationIp: CLIENT, sourcePort: 443, destinationPort: 53214, capturedLength: 1454, payloadLength: 1400, info: "Application Data" } : { info: "53214 → 443 [ACK] Seq=" + i * 1400 + " Ack=" + i * 3 + " Win=64240 Len=0" }));
  pk.usePacketsStore.getState().append(rows);
  pk.usePacketsStore.getState().select(6);

  const txs = ["api.github.com", "github.com", "github.githubassets.com", "raw.githubusercontent.com", "cdn.example.net", "www.google.com", "nope.invalid"].map((name, i) => ({
    id: i + 1, flowId: null, client: CLIENT, resolver: i % 4 === 3 ? "1.1.1.1" : "8.8.8.8", transactionId: 100 + i, queryName: name, queryType: i % 3 === 2 ? "AAAA" : "A", queryAt: t0 + i * 2e6, responseAt: name === "nope.invalid" ? t0 + i * 2e6 + 1.2e4 : t0 + i * 2e6 + 21000 + i * 4000,
    latency: name === "nope.invalid" ? 12000 : 21000 + i * 4000, responseCode: name === "nope.invalid" ? "NXDOMAIN" : "NOERROR", status: name === "nope.invalid" ? "failed" : "ok",
    answers: name === "nope.invalid" ? [] : [{ name, recordType: "A", data: servers[i % 5][0], ttl: 60 }],
  }));
  dn.useDnsStore.getState().apply({ transactions: txs, stats: { queries: 48, responses: 47, failures: 3, uniqueDomains: 31, avgLatency: 28400, p95Latency: 62000, resolvers: [{ ip: "8.8.8.8", queries: 38, failures: 2, avgLatency: 26000 }, { ip: "1.1.1.1", queries: 10, failures: 1, avgLatency: 34000 }] } });

  const evs = []; let eid = 1;
  const add = (dt, kind, title, detail, flowId = null, domain = null) => evs.push({ id: eid++, ts: t0 + dt, kind, flowId, host: "140.82.121.4", domain, title, detail });
  for (let k = 0; k < 6; k++) {
    const o = k * 2.2e6;
    add(o, "dnsQuery", "DNS " + txs[k].queryName, "A via 8.8.8.8", null, txs[k].queryName);
    add(o + 21e3, "dnsResponse", "DNS response 21 ms", txs[k].queryName + " → " + servers[k % 5][0], null, txs[k].queryName);
    add(o + 31e3, "flowStarted", "Flow started", "TCP 192.168.1.20:" + (53214 + k) + " → " + servers[k % 5][0] + ":443", k + 1);
    add(o + 52e3, "tcpConnect", "TCP connection established", "handshake RTT 21 ms", k + 1);
    add(o + 90e3, "tlsHandshake", "TLS 1.3 handshake", "SNI: " + txs[k].queryName, k + 1);
    if (k % 2) add(o + 1.1e6, "retransmission", "TCP retransmission", "to " + servers[k % 5][0] + ":443", k + 1);
    if (k === 3) add(o + 1.4e6, "trafficBurst", "Traffic burst", "5.4 MB/s, about 12× the recent average");
    add(o + 1.9e6, "flowEnded", "Connection closed", "after 1.9 s", k + 1);
  }
  ev.useEventsStore.getState().append(evs);

  const t = Math.floor(now / 1e6) - 300;
  const series = Array.from({ length: 300 }, (_, i) => ({ sec: t + i, span: 1, packets: 9000 + Math.round(Math.sin(i / 9) * 3000) + (i % 7) * 200, bytes: 0, bytesUp: 4e5 + Math.sin(i / 9) * 2e5, bytesDown: 3e6 + Math.sin(i / 14) * 2e6 + (i > 200 ? 4e6 : 0), newFlows: 3 + (i % 5), activeFlows: 60 + Math.round(Math.sin(i / 12) * 20), retransmissions: i % 11 === 0 ? 3 : 0, resets: 0, duplicateAcks: 0, zeroWindows: 0 }));
  const r = (key, bytes) => ({ key, bytes, packets: 1, flows: 1 });
  an.useAnalyticsStore.getState().set({ series, tcp: { packets: 120000, retransmissions: 2400, resets: 12, duplicateAcks: 55, zeroWindows: 2 }, dns: { queries: 48, responses: 47, failures: 3, uniqueDomains: 31, avgLatency: 28400, p95Latency: 182000, resolvers: [] },
    rankings: { hosts: servers.slice(0, 5).map(([ip, , b]) => r(ip, b)), domains: servers.slice(0, 5).map(([, d, b]) => r(d, b)), protocols: [r("TLS", 30e6), r("QUIC", 9e6), r("DNS", 2e5)], ports: [r("443/TCP", 30e6), r("443/UDP", 9e6), r("53/UDP", 2e5)], talkers: [r("192.168.1.20", 5e6), r("140.82.121.4", 18e6)] },
    problems: [{ id: "dns-latency", label: "potentialIssue", title: "High DNS latency", detail: "95% of lookups finished within 182 ms (average 28 ms). Slow resolvers delay every new connection." }, { id: "dns-failures", label: "worthInvestigating", title: "Repeated failed DNS resolutions", detail: "nope.invalid failed to resolve 3 times." }] });
  cp.useCaptureStore.getState().applyStats({ packets: 1423887, dropped: 12, bytes: 1.82e9, packetsPerSec: 12400, bytesPerSec: 8.7e6, bufferBytes: 134217728, parserLoad: 0.24, durationMs: 872000 });
  cp.useCaptureStore.getState().setState("capturing");
  cp.useCaptureStore.getState().selectInterface("eth0");
})()`;
