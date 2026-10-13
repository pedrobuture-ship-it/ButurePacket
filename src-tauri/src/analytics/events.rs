//! Turns what the parsers and engines observe into a chronological list of human-meaningful
//! events (DNS, connections, TLS, retransmissions, resets, latency spikes, bursts).

use std::collections::{HashMap, HashSet, VecDeque};

use serde::{Deserialize, Serialize};

use super::dns::{DnsStatus, DnsTransactionView};
use super::tls::TlsInfo;
use crate::flows::{Flow, Observed, TcpState};

const MAX_HISTORY: usize = 200_000;
const MAX_RETX_EVENTS_PER_FLOW: u32 = 20;
/// Bookkeeping sets are reset beyond this size so hostile traffic can't grow them without bound.
const MAX_TRACKING_ENTRIES: usize = 1_000_000;
const DNS_SPIKE_MICROS: i64 = 100_000;
const TCP_SPIKE_MICROS: i64 = 200_000;
const BURST_MIN_BYTES: u64 = 1_000_000;
const BURST_FACTOR: f64 = 5.0;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "camelCase")]
pub enum EventKind {
    DnsQuery,
    DnsResponse,
    DnsFailure,
    TcpConnect,
    TlsHandshake,
    FlowStarted,
    FlowEnded,
    Retransmission,
    Reset,
    LatencySpike,
    TrafficBurst,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct TimelineEvent {
    pub id: u64,
    /// Microseconds since the Unix epoch (capture clock).
    pub ts: i64,
    pub kind: EventKind,
    pub flow_id: Option<u64>,
    /// Remote address involved, when there is one.
    pub host: Option<String>,
    pub domain: Option<String>,
    pub title: String,
    pub detail: Option<String>,
}

#[derive(Debug, Default)]
struct Burst {
    sec: Option<i64>,
    bytes: u64,
    baseline: f64,
}

#[derive(Debug, Default)]
pub struct EventEngine {
    history: VecDeque<TimelineEvent>,
    fresh: Vec<TimelineEvent>,
    next_id: u64,
    retx_events: HashMap<u64, u32>,
    dns_query_announced: HashSet<u64>,
    dns_response_announced: HashSet<u64>,
    tls_announced: HashSet<u64>,
    burst: Burst,
}

fn fmt_ms(micros: i64) -> String {
    let ms = micros as f64 / 1000.0;
    if ms >= 100.0 {
        format!("{ms:.0} ms")
    } else {
        format!("{ms:.1} ms").replace(".0 ms", " ms")
    }
}

fn fmt_bytes(b: u64) -> String {
    const UNITS: [&str; 4] = ["B", "KB", "MB", "GB"];
    let (mut v, mut i) = (b as f64, 0);
    while v >= 1024.0 && i < UNITS.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{b} B")
    } else {
        format!("{v:.1} {}", UNITS[i])
    }
}

impl EventEngine {
    pub fn new() -> Self {
        Self {
            next_id: 1,
            ..Default::default()
        }
    }

    #[allow(clippy::too_many_arguments)] // flat event fields; a builder would only add noise
    fn push(
        &mut self,
        ts: i64,
        kind: EventKind,
        flow_id: Option<u64>,
        host: Option<String>,
        domain: Option<String>,
        title: impl Into<String>,
        detail: Option<String>,
    ) {
        self.trim_tracking();
        let ev = TimelineEvent {
            id: self.next_id,
            ts,
            kind,
            flow_id,
            host,
            domain,
            title: title.into(),
            detail,
        };
        self.next_id += 1;
        self.fresh.push(ev.clone());
        self.history.push_back(ev);
        while self.history.len() > MAX_HISTORY {
            self.history.pop_front();
        }
    }

    fn trim_tracking(&mut self) {
        if self.retx_events.len() > MAX_TRACKING_ENTRIES {
            self.retx_events.clear();
        }
        for set in [
            &mut self.dns_query_announced,
            &mut self.dns_response_announced,
            &mut self.tls_announced,
        ] {
            if set.len() > MAX_TRACKING_ENTRIES {
                set.clear();
            }
        }
    }

    fn flow_domain(f: &Flow) -> Option<String> {
        f.tls
            .as_ref()
            .and_then(|t| t.sni.clone())
            .or_else(|| f.domains.first().cloned())
    }

    fn remote(f: &Flow) -> String {
        f.endpoint_b.ip.to_string()
    }

    fn describe(f: &Flow) -> String {
        format!(
            "{} {}:{} → {}:{}",
            f.proto.name(),
            f.endpoint_a.ip,
            f.endpoint_a.port,
            f.endpoint_b.ip,
            f.endpoint_b.port
        )
    }

    /// Call after every packet that was folded into `flow`.
    pub fn flow_packet(&mut self, ts: i64, obs: &Observed, flow: &Flow) {
        let (id, domain, host) = (flow.id, Self::flow_domain(flow), Some(Self::remote(flow)));
        if obs.is_new {
            self.push(
                ts,
                EventKind::FlowStarted,
                Some(id),
                host.clone(),
                domain.clone(),
                "Flow started",
                Some(Self::describe(flow)),
            );
        }
        if flow.retransmissions > obs.retransmissions_before {
            let n = self.retx_events.entry(id).or_insert(0);
            *n += 1;
            if *n <= MAX_RETX_EVENTS_PER_FLOW {
                self.push(
                    ts,
                    EventKind::Retransmission,
                    Some(id),
                    host.clone(),
                    domain.clone(),
                    "TCP retransmission",
                    Some(format!(
                        "to {}:{}",
                        flow.endpoint_b.ip, flow.endpoint_b.port
                    )),
                );
            } else if *n == MAX_RETX_EVENTS_PER_FLOW + 1 {
                self.push(
                    ts,
                    EventKind::Retransmission,
                    Some(id),
                    host.clone(),
                    domain.clone(),
                    "More retransmissions on this flow (not listed individually)",
                    None,
                );
            }
        }
        if flow.resets > obs.resets_before {
            self.push(
                ts,
                EventKind::Reset,
                Some(id),
                host.clone(),
                domain.clone(),
                "Connection reset (RST)",
                Some(Self::describe(flow)),
            );
        }
        if flow.tcp_state != obs.state_before {
            match (obs.state_before, flow.tcp_state) {
                (Some(TcpState::SynSent | TcpState::SynReceived), Some(TcpState::Established)) => {
                    let detail = flow
                        .handshake_rtt_micros
                        .map(|r| format!("handshake RTT {}", fmt_ms(r)));
                    self.push(
                        ts,
                        EventKind::TcpConnect,
                        Some(id),
                        host.clone(),
                        domain.clone(),
                        "TCP connection established",
                        detail,
                    );
                    if let Some(rtt) = flow.handshake_rtt_micros.filter(|r| *r > TCP_SPIKE_MICROS) {
                        self.push(
                            ts,
                            EventKind::LatencySpike,
                            Some(id),
                            host.clone(),
                            domain.clone(),
                            "Latency spike",
                            Some(format!("TCP handshake took {}", fmt_ms(rtt))),
                        );
                    }
                }
                (_, Some(TcpState::Closed)) => self.push(
                    ts,
                    EventKind::FlowEnded,
                    Some(id),
                    host.clone(),
                    domain.clone(),
                    "Connection closed",
                    Some(format!("after {}", fmt_ms(flow.duration_micros()))),
                ),
                _ => {}
            }
        }
    }

    pub fn tls_update(&mut self, ts: i64, flow: &Flow, info: &TlsInfo) {
        if info.server_hello_at.is_some() && self.tls_announced.insert(flow.id) {
            let version = info.version.clone().unwrap_or_else(|| "TLS".into());
            self.push(
                info.server_hello_at.unwrap_or(ts),
                EventKind::TlsHandshake,
                Some(flow.id),
                Some(Self::remote(flow)),
                info.sni.clone().or_else(|| Self::flow_domain(flow)),
                format!("{version} handshake"),
                info.sni.as_ref().map(|s| format!("SNI: {s}")),
            );
        }
    }

    /// Feed the DNS transactions that changed in this batch.
    pub fn dns_changed(&mut self, views: &[DnsTransactionView]) {
        for v in views {
            if let Some(q) = v.query_at
                && self.dns_query_announced.insert(v.id)
            {
                self.push(
                    q,
                    EventKind::DnsQuery,
                    v.flow_id,
                    Some(v.resolver.to_string()),
                    Some(v.query_name.clone()),
                    format!("DNS {}", v.query_name),
                    Some(format!("{} via {}", v.query_type, v.resolver)),
                );
            }
            match (v.response_at, v.status) {
                (Some(r), DnsStatus::Ok) if self.dns_response_announced.insert(v.id) => {
                    let answers: Vec<&str> = v
                        .answers
                        .iter()
                        .filter(|a| a.record_type != "CNAME")
                        .map(|a| a.data.as_str())
                        .take(3)
                        .collect();
                    let title = v.latency.map_or("DNS response".to_string(), |l| {
                        format!("DNS response {}", fmt_ms(l))
                    });
                    self.push(
                        r,
                        EventKind::DnsResponse,
                        v.flow_id,
                        Some(v.resolver.to_string()),
                        Some(v.query_name.clone()),
                        title,
                        Some(format!(
                            "{} → {}",
                            v.query_name,
                            if answers.is_empty() {
                                "no addresses".into()
                            } else {
                                answers.join(", ")
                            }
                        )),
                    );
                    if let Some(l) = v.latency.filter(|l| *l > DNS_SPIKE_MICROS) {
                        self.push(
                            r,
                            EventKind::LatencySpike,
                            v.flow_id,
                            Some(v.resolver.to_string()),
                            Some(v.query_name.clone()),
                            "Latency spike",
                            Some(format!("DNS lookup took {}", fmt_ms(l))),
                        );
                    }
                }
                (Some(r), DnsStatus::Failed) if self.dns_response_announced.insert(v.id) => {
                    let code = v.response_code.clone().unwrap_or_default();
                    self.push(
                        r,
                        EventKind::DnsFailure,
                        v.flow_id,
                        Some(v.resolver.to_string()),
                        Some(v.query_name.clone()),
                        format!("DNS failure {code}"),
                        Some(v.query_name.clone()),
                    );
                }
                (None, DnsStatus::Timeout) if self.dns_response_announced.insert(v.id) => {
                    self.push(
                        v.query_at.unwrap_or(0),
                        EventKind::DnsFailure,
                        v.flow_id,
                        Some(v.resolver.to_string()),
                        Some(v.query_name.clone()),
                        "DNS timeout",
                        Some(format!("no response for {}", v.query_name)),
                    );
                }
                _ => {}
            }
        }
    }

    /// Account for `bytes` seen at `ts` and report bursts once their second has passed.
    pub fn bytes(&mut self, ts: i64, bytes: u64) {
        let sec = ts.div_euclid(1_000_000);
        match self.burst.sec {
            Some(s) if s == sec => self.burst.bytes += bytes,
            Some(s) if sec > s => {
                self.close_bucket(s);
                self.burst.sec = Some(sec);
                self.burst.bytes = bytes;
            }
            Some(_) => {} // late packet from an earlier second: ignore
            None => {
                self.burst.sec = Some(sec);
                self.burst.bytes = bytes;
            }
        }
    }

    fn close_bucket(&mut self, sec: i64) {
        let b = self.burst.bytes;
        let base = self.burst.baseline;
        if base > 0.0 && b >= BURST_MIN_BYTES && b as f64 > base * BURST_FACTOR {
            self.push(
                sec * 1_000_000,
                EventKind::TrafficBurst,
                None,
                None,
                None,
                "Traffic burst",
                Some(format!(
                    "{}/s, about {:.0}× the recent average",
                    fmt_bytes(b),
                    b as f64 / base
                )),
            );
        }
        self.burst.baseline = if base == 0.0 {
            b as f64
        } else {
            base * 0.8 + b as f64 * 0.2
        };
    }

    /// Events produced since the previous call.
    pub fn take_new(&mut self) -> Vec<TimelineEvent> {
        std::mem::take(&mut self.fresh)
    }

    pub fn snapshot(&self) -> Vec<TimelineEvent> {
        self.history.iter().cloned().collect()
    }

    pub fn clear(&mut self) {
        *self = Self::new();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::flows::{Endpoint, FlowEngine, FlowInput, Proto, TcpInfo};
    use crate::protocols::tcp::{ACK, FIN, RST, SYN};

    fn tcp(ts: i64, from_client: bool, flags: u16, seq: u32, ack: u32, len: u32) -> FlowInput {
        let c = Endpoint {
            ip: "192.168.1.20".parse().unwrap(),
            port: 53214,
        };
        let s = Endpoint {
            ip: "140.82.121.4".parse().unwrap(),
            port: 443,
        };
        let (src, dst) = if from_client { (c, s) } else { (s, c) };
        FlowInput {
            ts_micros: ts,
            src,
            dst,
            proto: Proto::Tcp,
            wire_len: 54 + len,
            tcp: Some(TcpInfo {
                seq,
                ack,
                flags,
                window: 64000,
                payload_len: len,
            }),
        }
    }

    fn feed(e: &mut FlowEngine, ev: &mut EventEngine, input: FlowInput) {
        let obs = e.observe_detailed(&input);
        ev.flow_packet(input.ts_micros, &obs, e.get(obs.id).unwrap());
    }

    fn kinds(ev: &mut EventEngine) -> Vec<EventKind> {
        ev.take_new().iter().map(|e| e.kind).collect()
    }

    #[test]
    fn connection_lifecycle_produces_ordered_events() {
        let (mut e, mut ev) = (FlowEngine::default(), EventEngine::new());
        feed(&mut e, &mut ev, tcp(1_000_000, true, SYN, 1000, 0, 0));
        feed(
            &mut e,
            &mut ev,
            tcp(1_021_000, false, SYN | ACK, 5000, 1001, 0),
        );
        feed(&mut e, &mut ev, tcp(1_021_500, true, ACK, 1001, 5001, 0));
        assert_eq!(
            kinds(&mut ev),
            vec![EventKind::FlowStarted, EventKind::TcpConnect]
        );
        feed(
            &mut e,
            &mut ev,
            tcp(2_000_000, true, FIN | ACK, 1001, 5001, 0),
        );
        feed(
            &mut e,
            &mut ev,
            tcp(2_000_100, false, FIN | ACK, 5001, 1002, 0),
        );
        let last = ev.take_new();
        assert_eq!(
            last.iter().map(|x| x.kind).collect::<Vec<_>>(),
            vec![EventKind::FlowEnded]
        );
        assert_eq!(last[0].title, "Connection closed");
    }

    #[test]
    fn tcp_connect_event_carries_rtt_and_flags_slow_handshakes() {
        let (mut e, mut ev) = (FlowEngine::default(), EventEngine::new());
        feed(&mut e, &mut ev, tcp(0, true, SYN, 1, 0, 0));
        feed(&mut e, &mut ev, tcp(300_000, false, SYN | ACK, 9, 2, 0));
        feed(&mut e, &mut ev, tcp(300_100, true, ACK, 2, 10, 0));
        let evs = ev.take_new();
        let connect = evs
            .iter()
            .find(|x| x.kind == EventKind::TcpConnect)
            .unwrap();
        assert_eq!(connect.detail.as_deref(), Some("handshake RTT 300 ms"));
        assert!(evs.iter().any(|x| x.kind == EventKind::LatencySpike));
    }

    #[test]
    fn retransmissions_and_resets_are_reported_and_capped() {
        let (mut e, mut ev) = (FlowEngine::default(), EventEngine::new());
        feed(&mut e, &mut ev, tcp(0, true, ACK, 1000, 1, 100));
        ev.take_new();
        for i in 0..30 {
            feed(&mut e, &mut ev, tcp(1000 + i, true, ACK, 1000, 1, 100));
        }
        let evs = ev.take_new();
        assert_eq!(
            evs.iter()
                .filter(|x| x.kind == EventKind::Retransmission)
                .count(),
            21
        ); // 20 + one "more" marker
        assert!(
            evs.last()
                .unwrap()
                .title
                .starts_with("More retransmissions")
        );
        feed(&mut e, &mut ev, tcp(9000, false, RST | ACK, 1, 1100, 0));
        assert_eq!(kinds(&mut ev), vec![EventKind::Reset]);
    }

    #[test]
    fn midstream_flow_does_not_invent_a_connect_event() {
        let (mut e, mut ev) = (FlowEngine::default(), EventEngine::new());
        feed(&mut e, &mut ev, tcp(0, true, ACK, 1000, 1, 100));
        assert_eq!(kinds(&mut ev), vec![EventKind::FlowStarted]);
    }

    #[test]
    fn tls_handshake_is_announced_once_with_sni() {
        let (mut e, mut ev) = (FlowEngine::default(), EventEngine::new());
        feed(&mut e, &mut ev, tcp(0, true, SYN, 1, 0, 0));
        ev.take_new();
        let f = e.get(1).unwrap().clone();
        let info = TlsInfo {
            version: Some("TLS 1.3".into()),
            sni: Some("github.com".into()),
            server_hello_at: Some(1_290_000),
            ..Default::default()
        };
        ev.tls_update(5, &f, &info);
        ev.tls_update(6, &f, &info);
        let evs = ev.take_new();
        assert_eq!(evs.len(), 1);
        assert_eq!(
            (evs[0].ts, evs[0].title.as_str(), evs[0].detail.as_deref()),
            (1_290_000, "TLS 1.3 handshake", Some("SNI: github.com"))
        );
        assert_eq!(evs[0].domain.as_deref(), Some("github.com"));
    }

    fn dns_view(
        id: u64,
        status: DnsStatus,
        latency: Option<i64>,
        rcode: &str,
    ) -> DnsTransactionView {
        use crate::analytics::dns::DnsAnswer;
        DnsTransactionView {
            id,
            flow_id: None,
            client: "192.168.1.20".parse().unwrap(),
            resolver: "8.8.8.8".parse().unwrap(),
            transaction_id: 1,
            query_name: "api.github.com".into(),
            query_type: "A".into(),
            query_at: Some(1_000),
            response_at: latency.map(|l| 1_000 + l),
            latency,
            response_code: Some(rcode.into()),
            status,
            answers: vec![DnsAnswer {
                name: "api.github.com".into(),
                record_type: "A".into(),
                data: "140.82.121.5".into(),
                ttl: 60,
            }],
        }
    }

    #[test]
    fn dns_query_then_response_are_announced_once_each() {
        let mut ev = EventEngine::new();
        ev.dns_changed(&[dns_view(1, DnsStatus::Pending, None, "")]);
        assert_eq!(kinds(&mut ev), vec![EventKind::DnsQuery]);
        let done = dns_view(1, DnsStatus::Ok, Some(21_000), "NOERROR");
        ev.dns_changed(std::slice::from_ref(&done));
        ev.dns_changed(std::slice::from_ref(&done));
        let evs = ev.take_new();
        assert_eq!(evs.len(), 1);
        assert_eq!(evs[0].title, "DNS response 21 ms");
        assert_eq!(
            evs[0].detail.as_deref(),
            Some("api.github.com → 140.82.121.5")
        );
    }

    #[test]
    fn dns_failures_timeouts_and_slow_lookups() {
        let mut ev = EventEngine::new();
        ev.dns_changed(&[
            dns_view(1, DnsStatus::Failed, Some(10_000), "NXDOMAIN"),
            dns_view(2, DnsStatus::Timeout, None, ""),
            dns_view(3, DnsStatus::Ok, Some(250_000), "NOERROR"),
        ]);
        let evs = ev.take_new();
        assert!(evs.iter().any(|e| e.title == "DNS failure NXDOMAIN"));
        assert!(evs.iter().any(|e| e.title == "DNS timeout"));
        assert!(evs.iter().any(|e| e.kind == EventKind::LatencySpike
            && e.detail.as_deref() == Some("DNS lookup took 250 ms")));
    }

    #[test]
    fn traffic_bursts_need_a_baseline_and_size() {
        let mut ev = EventEngine::new();
        for s in 0..5 {
            ev.bytes(s * 1_000_000 + 10, 100_000); // steady 100 KB/s
        }
        ev.bytes(5_000_000, 6_000_000); // a 6 MB second
        ev.bytes(6_000_000, 100_000); // closes the burst second
        ev.bytes(7_000_000, 100_000);
        let evs = ev.take_new();
        assert_eq!(evs.len(), 1);
        assert_eq!(evs[0].kind, EventKind::TrafficBurst);
        assert_eq!(evs[0].ts, 5_000_000);
        assert!(
            evs[0].detail.as_deref().unwrap().contains("MB/s")
                || evs[0].detail.as_deref().unwrap().contains("5.7 MB")
        );
    }

    #[test]
    fn small_variations_are_not_bursts() {
        let mut ev = EventEngine::new();
        for s in 0..10 {
            ev.bytes(s * 1_000_000, if s % 2 == 0 { 100_000 } else { 400_000 });
        }
        ev.bytes(11_000_000, 1);
        assert!(ev.take_new().is_empty());
    }

    #[test]
    fn history_snapshot_and_clear() {
        let mut ev = EventEngine::new();
        ev.dns_changed(&[dns_view(1, DnsStatus::Pending, None, "")]);
        assert_eq!(ev.snapshot().len(), 1);
        ev.take_new();
        assert_eq!(ev.snapshot().len(), 1);
        ev.clear();
        assert!(ev.snapshot().is_empty());
    }
}
