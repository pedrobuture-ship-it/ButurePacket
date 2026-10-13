//! Packet → parser → flow engine → (later: correlation, analytics). One place where a batch is processed.

use std::sync::Mutex;

use crate::analytics::dns::{DnsStats, DnsTracker, DnsTransactionView};
use crate::analytics::events::{EventEngine, TimelineEvent};
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
}

impl Pipeline {
    pub fn process(&self, batch: Vec<RawPacket>) -> Processed {
        let mut packets = Vec::with_capacity(batch.len());
        let mut flows = self.flows.lock().unwrap();
        let mut dns = self.dns.lock().unwrap();
        let mut tls = self.tls.lock().unwrap();
        let mut events = self.events.lock().unwrap();
        for raw in &batch {
            let d = dissect(&raw.data);
            let mut summary = summarize_dissection(raw, &d);
            if let Some(input) = FlowInput::from_dissection(raw, &d) {
                let obs = flows.observe_detailed(&input);
                let id = obs.id;
                events.bytes(input.ts_micros, u64::from(input.wire_len));
                summary.flow_id = Some(id);
                if let Some(msg) = &d.dns {
                    dns.observe(
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
            packets.push(summary);
        }
        let changed = flows.take_changed();
        let dns_changed = dns.take_changed();
        let dns_stats = dns.take_stats_if_changed();
        events.dns_changed(&dns_changed);
        let mut new_events = events.take_new();
        new_events.truncate(MAX_EVENTS_PER_BATCH);
        drop((flows, dns, tls, events));
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

    pub fn clear(&self) {
        self.store.lock().unwrap().clear();
        self.flows.lock().unwrap().clear();
        self.dns.lock().unwrap().clear();
        self.tls.lock().unwrap().clear();
        self.events.lock().unwrap().clear();
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
}
