//! Packet → parser → flow engine → (later: correlation, analytics). One place where a batch is processed.

use std::sync::Mutex;

use crate::analytics::dns::{DnsStats, DnsTracker, DnsTransactionView};
use crate::analytics::events::{EventEngine, TimelineEvent};
use crate::analytics::metrics::{AnalyticsSnapshot, MetricsEngine};
use crate::analytics::tls::TlsTracker;
use crate::capture::RawPacket;
use crate::flows::{Direction, FlowEngine, FlowInput, FlowView, Proto};
use crate::protocols::{PacketSummary, dissect, summary::summarize_dissection};
use crate::storage::memory::PacketStore;

/// What one processed batch produced for the UI.
#[derive(Debug, Default)]
pub struct Processed {
    pub packets: Vec<PacketSummary>,
    pub flows: Vec<FlowView>,
    pub dns: Vec<DnsTransactionView>,
    pub dns_stats: Option<DnsStats>,
    pub events: Vec<TimelineEvent>,
}

/// Upper bound on events pushed to the UI per batch (the full history stays in memory).
const MAX_EVENTS_PER_BATCH: usize = 5_000;

#[derive(Default)]
pub struct Pipeline {
    pub store: Mutex<PacketStore>,
    pub flows: Mutex<FlowEngine>,
    pub dns: Mutex<DnsTracker>,
    pub tls: Mutex<TlsTracker>,
    pub events: Mutex<EventEngine>,
    pub metrics: Mutex<MetricsEngine>,
}

impl Pipeline {
    pub fn process(&self, batch: Vec<RawPacket>) -> Processed {
        let mut packets = Vec::with_capacity(batch.len());
        let mut flows = self.flows.lock().unwrap();
        let mut dns = self.dns.lock().unwrap();
        let mut tls = self.tls.lock().unwrap();
        let mut events = self.events.lock().unwrap();
        let mut metrics = self.metrics.lock().unwrap();
        for raw in &batch {
            let d = dissect(&raw.data);
            let mut summary = summarize_dissection(raw, &d);
            let mut observed = None;
            if let Some(input) = FlowInput::from_dissection(raw, &d) {
                let obs = flows.observe_detailed(&input);
                observed = Some(obs);
                let id = obs.id;
                events.bytes(input.ts_micros, u64::from(input.wire_len));
                summary.flow_id = Some(id);
                if let Some(msg) = &d.dns {
                    summary.latency = dns.observe(
                        input.ts_micros,
                        input.src.ip,
                        input.src.port,
                        input.dst.ip,
                        input.dst.port,
                        Some(id),
                        msg,
                    );
                }
                if let Some(f) = flows.get(id) {
                    events.flow_packet(input.ts_micros, &obs, f);
                }
                if let Some(t) = input.tcp
                    && t.payload_len > 0
                    && let Some(payload) = raw
                        .data
                        .get(d.payload_offset..d.payload_offset + d.payload_len)
                {
                    let a_to_b = flows
                        .get(id)
                        .is_none_or(|f| f.direction_of(&input.src) == Direction::AtoB);
                    if let Some(info) = tls.observe(id, a_to_b, input.ts_micros, t.seq, payload) {
                        if let Some(f) = flows.get(id) {
                            events.tls_update(input.ts_micros, f, &info);
                        }
                        flows.set_tls(id, info);
                    }
                }
                if input.proto != Proto::Icmp {
                    attach_likely_domains(&mut flows, &dns, id, input.ts_micros);
                }
            }
            metrics.observe(
                raw.ts_micros,
                raw.original_len.max(raw.captured_len),
                observed
                    .as_ref()
                    .and_then(|o| flows.get(o.id).map(|f| (o, f))),
            );
            packets.push(summary);
        }
        let changed = flows.take_changed();
        let dns_changed = dns.take_changed();
        let dns_stats = dns.take_stats_if_changed();
        events.dns_changed(&dns_changed);
        let mut new_events = events.take_new();
        new_events.truncate(MAX_EVENTS_PER_BATCH);
        drop((flows, dns, tls, events, metrics));
        let mut store = self.store.lock().unwrap();
        for raw in batch {
            store.push(raw);
        }
        Processed {
            packets,
            flows: changed,
            dns: dns_changed,
            dns_stats,
            events: new_events,
        }
    }

    /// Rolling metrics, rankings and potential problems for the Analytics screen.
    pub fn analytics(&self, whole: bool) -> AnalyticsSnapshot {
        let flows = self.flows.lock().unwrap();
        let dns = self.dns.lock().unwrap();
        let metrics = self.metrics.lock().unwrap();
        metrics.snapshot(
            flows.snapshot_flows(),
            dns.stats(),
            &dns.failed_domains(),
            whole,
        )
    }

    pub fn clear(&self) {
        self.store.lock().unwrap().clear();
        self.flows.lock().unwrap().clear();
        self.dns.lock().unwrap().clear();
        self.tls.lock().unwrap().clear();
        self.events.lock().unwrap().clear();
        self.metrics.lock().unwrap().clear();
    }
}

/// Flows get "likely domain" hints from earlier DNS answers for the remote address.
/// A flow only gets hints once, when it has none yet and has just started.
fn attach_likely_domains(flows: &mut FlowEngine, dns: &DnsTracker, id: u64, ts: i64) {
    let Some(f) = flows.get(id) else { return };
    if !f.domains.is_empty() || f.total_packets() > 3 {
        return;
    }
    // The server side is the more informative endpoint; fall back to the other one.
    let mut found = dns.likely_domains(f.endpoint_b.ip, ts);
    if found.is_empty() {
        found = dns.likely_domains(f.endpoint_a.ip, ts);
    }
    if !found.is_empty() {
        flows.add_domains(id, &found);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analytics::events::EventKind;
    use etherparse::PacketBuilder;

    fn frame(id: u64, sport: u16) -> RawPacket {
        let b = PacketBuilder::ethernet2([1; 6], [2; 6])
            .ipv4([10, 0, 0, 1], [10, 0, 0, 2], 64)
            .udp(sport, 53);
        let mut data = vec![];
        b.write(&mut data, b"x").unwrap();
        RawPacket {
            id,
            ts_micros: id as i64 * 1000,
            captured_len: data.len() as u32,
            original_len: data.len() as u32,
            data,
        }
    }

    #[test]
    fn batch_produces_summaries_flows_and_stores_raw() {
        let p = Pipeline::default();
        let out = p.process(vec![frame(1, 5000), frame(2, 5000), frame(3, 6000)]);
        assert_eq!(out.packets.len(), 3);
        assert_eq!(out.flows.len(), 2);
        assert_eq!(out.packets[0].flow_id, out.packets[1].flow_id);
        assert_ne!(out.packets[0].flow_id, out.packets[2].flow_id);
        assert!(out.packets[0].flow_id.is_some());
        assert_eq!(p.store.lock().unwrap().get(2).unwrap().id, 2);
        // second batch only reports flows that changed
        let out = p.process(vec![frame(4, 6000)]);
        assert_eq!(out.flows.len(), 1);
        assert_eq!(out.flows[0].total_packets, 2);
    }

    #[test]
    fn dns_answers_become_likely_domains_for_later_flows() {
        use crate::protocols::dns::tests::{query, response};
        let p = Pipeline::default();
        let dns_frame =
            |id: u64, src: [u8; 4], dst: [u8; 4], sp: u16, dp: u16, payload: Vec<u8>| {
                let b = PacketBuilder::ethernet2([1; 6], [2; 6])
                    .ipv4(src, dst, 64)
                    .udp(sp, dp);
                let mut data = vec![];
                b.write(&mut data, &payload).unwrap();
                RawPacket {
                    id,
                    ts_micros: id as i64 * 10_000,
                    captured_len: data.len() as u32,
                    original_len: data.len() as u32,
                    data,
                }
            };
        let tcp_syn = |id: u64| {
            let b = PacketBuilder::ethernet2([1; 6], [2; 6])
                .ipv4([10, 0, 0, 1], [140, 82, 121, 5], 64)
                .tcp(40000, 443, 1, 1000)
                .syn();
            let mut data = vec![];
            b.write(&mut data, &[]).unwrap();
            RawPacket {
                id,
                ts_micros: id as i64 * 10_000,
                captured_len: data.len() as u32,
                original_len: data.len() as u32,
                data,
            }
        };
        let out = p.process(vec![
            dns_frame(
                1,
                [10, 0, 0, 1],
                [8, 8, 8, 8],
                5555,
                53,
                query(9, "api.github.com", 1),
            ),
            dns_frame(
                2,
                [8, 8, 8, 8],
                [10, 0, 0, 1],
                53,
                5555,
                response(9, "api.github.com", None, &[[140, 82, 121, 5]], 60, 0),
            ),
            tcp_syn(3),
        ]);
        assert_eq!(out.dns.len(), 1);
        assert_eq!(out.dns[0].latency, Some(10_000));
        assert!(out.dns_stats.is_some());
        let tcp = out.flows.iter().find(|f| f.protocol == "TCP").unwrap();
        assert_eq!(tcp.domains, vec!["api.github.com"]);
        let dns_flow = out.flows.iter().find(|f| f.protocol == "UDP").unwrap();
        assert!(dns_flow.domains.is_empty());
        assert_eq!(out.packets[1].application_protocol.as_deref(), Some("DNS"));
        assert_eq!(out.packets[1].latency, Some(10_000));
        assert_eq!(out.packets[0].domain.as_deref(), Some("api.github.com"));
        assert_eq!(out.packets[0].latency, None);
        let kinds: Vec<_> = out.events.iter().map(|e| e.kind).collect();
        for k in [
            EventKind::DnsQuery,
            EventKind::DnsResponse,
            EventKind::FlowStarted,
        ] {
            assert!(kinds.contains(&k), "missing {k:?} in {kinds:?}");
        }
    }

    #[test]
    fn tls_handshake_populates_flow_metadata_and_packet_info() {
        use crate::protocols::tls::tests::{client_hello, server_hello};
        let p = Pipeline::default();
        let seg = |id: u64, from_client: bool, seq: u32, payload: &[u8]| {
            let (s, d, sp, dp) = if from_client {
                ([10, 0, 0, 1], [140, 82, 121, 4], 40000, 443)
            } else {
                ([140, 82, 121, 4], [10, 0, 0, 1], 443, 40000)
            };
            let b = PacketBuilder::ethernet2([1; 6], [2; 6])
                .ipv4(s, d, 64)
                .tcp(sp, dp, seq, 1000)
                .ack(1);
            let mut data = vec![];
            b.write(&mut data, payload).unwrap();
            RawPacket {
                id,
                ts_micros: id as i64 * 10_000,
                captured_len: data.len() as u32,
                original_len: data.len() as u32,
                data,
            }
        };
        let out = p.process(vec![
            seg(1, true, 1000, &client_hello("github.com", &["h2"])),
            seg(2, false, 5000, &server_hello(true, 0x1301, None)),
        ]);
        assert_eq!(out.packets[0].info, "Client Hello (SNI: github.com)");
        assert_eq!(out.packets[0].application_protocol.as_deref(), Some("TLS"));
        assert_eq!(out.packets[1].info, "Server Hello");
        let f = out.flows.iter().find(|f| f.protocol == "TCP").unwrap();
        let tls = f.tls.as_ref().unwrap();
        assert_eq!(
            (tls.sni.as_deref(), tls.version.as_deref()),
            (Some("github.com"), Some("TLS 1.3"))
        );
        assert_eq!(f.application_protocol.as_deref(), Some("TLS"));
    }

    #[test]
    fn clear_empties_everything() {
        let p = Pipeline::default();
        p.process(vec![frame(1, 5000)]);
        p.clear();
        assert!(p.store.lock().unwrap().is_empty());
        assert!(p.flows.lock().unwrap().is_empty());
    }

    /// A realistic capture file (DNS lookup, TCP handshake, TLS hello, close) read from disk
    /// and pushed through the same path the UI uses.
    #[test]
    fn capture_file_end_to_end() {
        use crate::capture::file::write_pcap;
        use crate::capture::offline::{self, OfflineSink, Progress};
        use crate::protocols::dns::tests::{query, response};
        use crate::protocols::tls::tests::{client_hello, server_hello};
        use std::sync::atomic::AtomicBool;

        let client = [192, 168, 1, 20];
        let resolver = [8, 8, 8, 8];
        let server = [140, 82, 121, 4];
        let mut frames: Vec<(i64, Vec<u8>)> = vec![];
        let eth = || PacketBuilder::ethernet2([1; 6], [2; 6]);
        let mut add =
            |ts_ms: i64, data: Vec<u8>| frames.push((1_700_000_000_000_000 + ts_ms * 1000, data));
        let udp = |src: [u8; 4], dst: [u8; 4], sp: u16, dp: u16, payload: &[u8]| {
            let mut d = vec![];
            eth()
                .ipv4(src, dst, 64)
                .udp(sp, dp)
                .write(&mut d, payload)
                .unwrap();
            d
        };
        let tcp =
            |from_client: bool, seq: u32, ack: u32, flags: (bool, bool, bool), payload: &[u8]| {
                let (s, d, sp, dp) = if from_client {
                    (client, server, 40000, 443)
                } else {
                    (server, client, 443, 40000)
                };
                let mut b = eth().ipv4(s, d, 64).tcp(sp, dp, seq, 64000);
                if flags.0 {
                    b = b.syn();
                }
                if flags.1 {
                    b = b.ack(ack);
                }
                if flags.2 {
                    b = b.fin();
                }
                let mut out = vec![];
                b.write(&mut out, payload).unwrap();
                out
            };
        add(
            0,
            udp(client, resolver, 5555, 53, &query(9, "api.github.com", 1)),
        );
        add(
            21,
            udp(
                resolver,
                client,
                53,
                5555,
                &response(9, "api.github.com", None, &[[140, 82, 121, 4]], 60, 0),
            ),
        );
        add(30, tcp(true, 1000, 0, (true, false, false), &[]));
        add(50, tcp(false, 5000, 1001, (true, true, false), &[]));
        add(50, tcp(true, 1001, 5001, (false, true, false), &[]));
        let hello = client_hello("api.github.com", &["h2"]);
        add(60, tcp(true, 1001, 5001, (false, true, false), &hello));
        add(
            90,
            tcp(
                false,
                5001,
                1001 + hello.len() as u32,
                (false, true, false),
                &server_hello(true, 0x1301, None),
            ),
        );
        add(
            500,
            tcp(
                true,
                1001 + hello.len() as u32,
                5400,
                (false, true, true),
                &[],
            ),
        );

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("e2e.pcap");
        let raws: Vec<RawPacket> = frames
            .iter()
            .map(|(ts, d)| RawPacket {
                id: 0,
                ts_micros: *ts,
                captured_len: d.len() as u32,
                original_len: d.len() as u32,
                data: d.clone(),
            })
            .collect();
        write_pcap(std::fs::File::create(&path).unwrap(), raws.iter()).unwrap();

        struct Sink<'a>(&'a Pipeline, std::sync::Mutex<Vec<Processed>>);
        impl OfflineSink for Sink<'_> {
            fn progress(&self, _: &Progress) {}
            fn batch(&self, packets: Vec<RawPacket>) {
                self.1.lock().unwrap().push(self.0.process(packets));
            }
        }
        let p = Pipeline::default();
        let sink = Sink(&p, Default::default());
        let out = offline::run(&path, &AtomicBool::new(false), &sink).unwrap();
        assert_eq!(out.packets, 8);

        let outs = sink.1.lock().unwrap();
        let packets: Vec<_> = outs.iter().flat_map(|o| o.packets.iter()).collect();
        assert_eq!(packets.len(), 8);
        assert_eq!(packets[0].info, "Standard query A api.github.com");
        assert_eq!(packets[1].latency, Some(21_000));
        assert_eq!(packets[5].info, "Client Hello (SNI: api.github.com)");
        assert_eq!(packets[6].info, "Server Hello");

        let flows = p.flows.lock().unwrap().snapshot();
        let tcp_flow = flows.iter().find(|f| f.protocol == "TCP").unwrap();
        assert_eq!(tcp_flow.latency, Some(20_000)); // SYN → SYN/ACK
        assert_eq!(tcp_flow.domains, vec!["api.github.com"]); // from the earlier DNS answer
        let tls = tcp_flow.tls.as_ref().unwrap();
        assert_eq!(
            (tls.version.as_deref(), tls.sni.as_deref()),
            (Some("TLS 1.3"), Some("api.github.com"))
        );
        assert_eq!(flows.len(), 2);

        let kinds: Vec<_> = outs
            .iter()
            .flat_map(|o| o.events.iter().map(|e| e.kind))
            .collect();
        for k in [
            EventKind::DnsQuery,
            EventKind::DnsResponse,
            EventKind::FlowStarted,
            EventKind::TcpConnect,
            EventKind::TlsHandshake,
        ] {
            assert!(kinds.contains(&k), "missing {k:?}");
        }
        let snap = p.analytics(false);
        assert_eq!(snap.tcp.packets, 6);
        assert_eq!(snap.dns.queries, 1);
        assert!(snap.rankings.protocols.iter().any(|r| r.key == "TLS"));
        assert!(snap.problems.is_empty());
    }
}
