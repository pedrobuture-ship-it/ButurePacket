import { endpointText } from "@/features/flows/flowText";
import { formatBytes, formatLatency } from "@/lib/format";
import type { DnsTransaction, FlowView, TimelineEvent } from "@/types/ipc";

/** One sentence plus, for inferences, what it is based on. */
export interface StoryStep {
  text: string;
  /** Why we believe it. Required for inferred steps. */
  basis?: string;
}

export interface Story {
  /** Facts read directly from captured packets, in chronological order. */
  observed: StoryStep[];
  /** Interpretations that go beyond the packets. Never to be read as fact. */
  inferred: StoryStep[];
}

const WORDS = ["zero", "one", "two", "three", "four", "five", "six", "seven", "eight", "nine", "ten"];

export function countWord(n: number): string {
  return n >= 0 && n <= 10 ? WORDS[n] : n.toLocaleString("en-US");
}

const capitalize = (s: string) => s.charAt(0).toUpperCase() + s.slice(1);
const plural = (n: number, one: string, many = `${one}s`) => (n === 1 ? one : many);

/** 8_400_000 → "8.4 seconds", 125_000_000 → "2 minutes 5 seconds". */
export function formatSpanLong(micros: number): string {
  const s = Math.max(0, micros) / 1e6;
  if (s < 60) {
    const v = s < 10 ? s.toFixed(1).replace(/\.0$/, "") : String(Math.round(s));
    return `${v} ${v === "1" ? "second" : "seconds"}`;
  }
  const total = Math.round(s);
  const h = Math.floor(total / 3600);
  const m = Math.floor((total % 3600) / 60);
  const sec = total % 60;
  const parts = [h && `${h} ${plural(h, "hour")}`, m && `${m} ${plural(m, "minute")}`, !h && sec && `${sec} ${plural(sec, "second")}`].filter(Boolean);
  return parts.join(" ");
}

/** The most recent DNS exchange from this client that returned the flow's server address. */
export function findDnsLookup(flow: FlowView, dns: Iterable<DnsTransaction>): DnsTransaction | null {
  let best: DnsTransaction | null = null;
  for (const t of dns) {
    if (t.status !== "ok") continue;
    const when = t.responseAt ?? t.queryAt;
    if (when === null || when > flow.startedAt) continue; // the answer must precede the connection
    if (t.client !== flow.endpointA.ip) continue;
    if (!t.answers.some((a) => (a.recordType === "A" || a.recordType === "AAAA") && a.data === flow.endpointB.ip)) continue;
    if (!best || when > (best.responseAt ?? best.queryAt ?? 0)) best = t;
  }
  return best;
}

export function buildStory(flow: FlowView, events: readonly TimelineEvent[], dns: Iterable<DnsTransaction>): Story {
  const observed: StoryStep[] = [];
  const inferred: StoryStep[] = [];
  const server = endpointText(flow.endpointB, true);
  const isTcp = flow.protocol === "TCP";
  const hasEvent = (kind: TimelineEvent["kind"]) => events.some((e) => e.kind === kind);

  // --- name resolution ---
  const lookup = findDnsLookup(flow, dns);
  if (lookup) {
    observed.push({ text: `Your device queried ${lookup.queryName} using DNS (${lookup.queryType} record, via ${lookup.resolver}).` });
    if (lookup.latency !== null) observed.push({ text: `DNS responded after ${formatLatency(lookup.latency)}.` });
    observed.push({ text: `The DNS answer included ${flow.endpointB.ip}, the address this connection went to.` });
    inferred.push({
      text: `This connection was probably made to ${lookup.queryName}.`,
      basis: "The DNS answer and the connection share an address and the answer came first. Other names can share the same address.",
    });
  } else if (flow.domains.length > 0) {
    inferred.push({ text: `The destination is likely ${flow.domains[0]}.`, basis: "A recent DNS answer pointed that name at this address." });
  }

  // --- transport ---
  if (isTcp) {
    if (hasEvent("tcpConnect") || flow.latency !== null) {
      const rtt = flow.latency !== null ? ` (handshake took ${formatLatency(flow.latency)})` : "";
      observed.push({ text: `A TCP connection was opened to ${server}${rtt}.` });
    } else {
      observed.push({ text: `Traffic to ${server} was already in progress when the capture began; the TCP handshake was not seen.` });
    }
  } else {
    observed.push({ text: `${flow.protocol} packets were exchanged with ${server}.` });
  }

  // --- TLS ---
  const tls = flow.tls;
  if (tls) {
    if (tls.sni) observed.push({ text: `The client asked for the server name ${tls.sni} (TLS SNI).` });
    if (tls.version) observed.push({ text: `${tls.version} was negotiated${tls.cipherSuite ? ` with ${tls.cipherSuite}` : ""}.` });
    else observed.push({ text: "A TLS handshake started, but the negotiated version was not captured." });
    if (tls.alpnSelected) observed.push({ text: `The application protocol ${tls.alpnSelected} was selected (ALPN).` });
    if (tls.certificate?.subjectCn) observed.push({ text: `The server presented a certificate for ${tls.certificate.subjectCn}${tls.certificate.issuerCn ? `, issued by ${tls.certificate.issuerCn}` : ""}.` });
    else if (tls.handshakeEncrypted) observed.push({ text: "Certificate details are encrypted in TLS 1.3 and cannot be shown." });
    inferred.push({ text: "The content of this connection is encrypted, so what was exchanged cannot be known from the capture.", basis: "TLS was used." });
    if (tls.alpnSelected === "h2" || (!tls.alpnSelected && tls.alpnOffered.includes("h2") && flow.endpointB.port === 443)) {
      inferred.push({ text: "This was probably web or API traffic over HTTPS.", basis: tls.alpnSelected ? "ALPN selected h2." : "The client offered h2 on port 443." });
    }
  }

  // --- volume and duration ---
  observed.push({ text: `The connection ${isTcp ? "remained active" : "was active"} for ${formatSpanLong(flow.duration)}.` });
  observed.push({ text: `${formatBytes(flow.bytesBToA)} were received.` });
  observed.push({ text: `${formatBytes(flow.bytesAToB)} were sent.` });

  // --- trouble ---
  if (flow.retransmissions > 0) observed.push({ text: `${capitalize(countWord(flow.retransmissions))} ${plural(flow.retransmissions, "retransmission")} ${flow.retransmissions === 1 ? "was" : "were"} observed.` });
  if (flow.duplicateAcks >= 3) observed.push({ text: `${capitalize(countWord(flow.duplicateAcks))} duplicate acknowledgements were observed.` });
  if (flow.zeroWindows > 0) observed.push({ text: `The receiver advertised a zero window ${countWord(flow.zeroWindows)} ${plural(flow.zeroWindows, "time")}, asking the sender to pause.` });
  if (flow.retransmissions > 0 || flow.duplicateAcks >= 3) {
    inferred.push({
      text: "Some packets may have been lost or delayed on the way.",
      basis: "Retransmissions and duplicate ACKs usually follow packet loss, but a capture can also miss packets that were delivered fine.",
    });
  }
  if (flow.latency !== null && flow.latency > 200_000) inferred.push({ text: "The server or the network path was slow to answer.", basis: `The handshake took ${formatLatency(flow.latency)}.` });

  // --- ending ---
  if (flow.resets > 0 || flow.tcpState === "RESET") observed.push({ text: "The connection was ended with a reset (RST)." });
  else if (flow.tcpState === "CLOSED") observed.push({ text: "The connection closed normally." });
  else if (isTcp) observed.push({ text: "The connection was still open at the last captured packet." });
  if (flow.resets > 0) inferred.push({ text: "One side refused or abandoned the connection.", basis: "A reset is sent when a host rejects a connection or discards its state; the reason is not in the packets." });

  return { observed, inferred };
}

/** Plain-text rendering, for copy/paste. */
export function storyToText(story: Story): string {
  const lines = ["Observed", ...story.observed.map((s, i) => `${i + 1}. ${s.text}`)];
  if (story.inferred.length) lines.push("", "Inferred (not directly observed)", ...story.inferred.map((s) => `- ${s.text} (${s.basis})`));
  return lines.join("\n");
}
