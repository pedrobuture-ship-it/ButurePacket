//! Packet → parser → flow engine → (later: correlation, analytics). One place where a batch is processed.

use crate::util::LockRecover;
use std::path::Path;
use std::sync::{Arc, Mutex};

use crate::analytics::dns::{DnsStats, DnsTracker, DnsTransactionView};
use crate::analytics::events::{EventEngine, TimelineEvent};
use crate::analytics::metrics::{AnalyticsSnapshot, MetricsEngine};
use crate::analytics::tls::TlsTracker;
use crate::capture::CaptureError;
use crate::capture::RawPacket;
use crate::flows::{Direction, FlowEngine, FlowInput, FlowView, Proto};
use crate::protocols::{PacketSummary, dissect, summary::summarize_dissection};
use crate::storage::database::Database;
use crate::storage::memory::PacketStore;
use crate::storage::writer::{Job, StorageConfig, StorageStatus, StorageWriter};

/// What one processed batch produced: the per-packet rows. Everything else (flows, DNS, events)
/// accumulates inside the engines and is collected by [`Pipeline::drain_updates`] a few times a
/// second, so a busy link doesn't re-send thousands of flow updates every batch.
#[derive(Debug, Default)]
pub struct Processed {
    /// Shared so the UI event and the database writer don't each need their own copy.
    pub packets: Arc<Vec<PacketSummary>>,
}

/// Changes accumulated since the last drain.
#[derive(Debug, Default)]
pub struct Updates {
    pub flows: Vec<FlowView>,
    pub dns: Vec<DnsTransactionView>,
    pub dns_stats: Option<DnsStats>,
    pub events: Vec<TimelineEvent>,
}

impl Updates {
    pub fn is_empty(&self) -> bool {
        self.flows.is_empty()
            && self.dns.is_empty()
            && self.dns_stats.is_none()
            && self.events.is_empty()
    }
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
    /// Background SQLite writer for the capture in progress, if persistence is on.
    storage: Mutex<Option<StorageWriter>>,
}

impl Pipeline {
    pub fn process(&self, batch: Vec<RawPacket>) -> Processed {
        let mut packets = Vec::with_capacity(batch.len());
        let mut flows = self.flows.lock_recover();
        let mut dns = self.dns.lock_recover();
        let mut tls = self.tls.lock_recover();
        let mut events = self.events.lock_recover();
        let mut metrics = self.metrics.lock_recover();
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
        drop((flows, dns, tls, events, metrics));
        let mut store = self.store.lock_recover();
        for raw in batch {
            store.push(raw);
        }
        drop(store);
        let packets = Arc::new(packets);
        if let Some(w) = self.storage.lock_recover().as_ref() {
            w.submit(Job::Packets(packets.clone()));
        }
        Processed { packets }
    }

    /// Collects flow, DNS and event changes since the previous call (and persists them).
    pub fn drain_updates(&self) -> Updates {
        let mut flows = self.flows.lock_recover();
        let mut dns = self.dns.lock_recover();
        let mut events = self.events.lock_recover();
        let changed = flows.take_changed();
        let dns_changed = dns.take_changed();
        let dns_stats = dns.take_stats_if_changed();
        events.dns_changed(&dns_changed);
        let mut new_events = events.take_new();
        new_events.truncate(MAX_EVENTS_PER_BATCH);
        drop((flows, dns, events));
        if let Some(w) = self.storage.lock_recover().as_ref() {
            if !changed.is_empty() {
                w.submit(Job::Flows(changed.clone()));
            }
            if !dns_changed.is_empty() {
                w.submit(Job::Dns(dns_changed.clone()));
            }
            if !new_events.is_empty() {
                w.submit(Job::Events(new_events.clone()));
            }
        }
        Updates {
            flows: changed,
            dns: dns_changed,
            dns_stats,
            events: new_events,
        }
    }

    /// `process`, but a bug that panics on some unforeseen packet skips that batch instead of
    /// taking down the capture thread. The panic message is returned for reporting.
    pub fn process_guarded(&self, batch: Vec<RawPacket>) -> Result<Processed, String> {
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| self.process(batch))).map_err(
            |payload| {
                payload
                    .downcast_ref::<&str>()
                    .map(|s| (*s).to_string())
                    .or_else(|| payload.downcast_ref::<String>().cloned())
                    .unwrap_or_else(|| "unknown error".to_string())
            },
        )
    }

    /// Starts persisting everything processed from now on into the database at `path`.
    pub fn attach_storage(
        &self,
        path: &Path,
        config: StorageConfig,
        source: &str,
    ) -> Result<(), CaptureError> {
        let db = Database::open(path)?;
        db.set_meta("source", source)?;
        let writer = StorageWriter::start(db, config)?;
        if let Some(old) = self.storage.lock_recover().replace(writer) {
            let _ = old.finish();
        }
        Ok(())
    }

    /// Flushes and closes the database, if one is attached.
    pub fn detach_storage(&self) -> Option<Result<StorageStatus, CaptureError>> {
        let writer = self.storage.lock_recover().take()?;
        Some(writer.finish())
    }

    pub fn storage_status(&self) -> Option<StorageStatus> {
        self.storage
            .lock_recover()
            .as_ref()
            .map(StorageWriter::status)
    }

    /// One flow with its sparkline, for the inspector.
    pub fn flow_detail(&self, id: u64) -> Option<FlowView> {
        self.flows.lock_recover().detailed(id)
    }

    /// Rolling metrics, rankings and potential problems for the Analytics screen.
    pub fn analytics(&self, whole: bool) -> AnalyticsSnapshot {
        let flows = self.flows.lock_recover();
        let dns = self.dns.lock_recover();
        let metrics = self.metrics.lock_recover();
        metrics.snapshot(
            flows.snapshot_flows(),
            dns.stats(),
            &dns.failed_domains(),
            whole,
        )
    }

    pub fn clear(&self) {
        self.store.lock_recover().clear();
        self.flows.lock_recover().clear();
        self.dns.lock_recover().clear();
        self.tls.lock_recover().clear();
        self.events.lock_recover().clear();
        self.metrics.lock_recover().clear();
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
        let up = p.drain_updates();
        assert_eq!(out.packets.len(), 3);
        assert_eq!(up.flows.len(), 2);
        assert_eq!(out.packets[0].flow_id, out.packets[1].flow_id);
        assert_ne!(out.packets[0].flow_id, out.packets[2].flow_id);
        assert!(out.packets[0].flow_id.is_some());
        assert_eq!(p.store.lock_recover().get(2).unwrap().id, 2);
        // second batch only reports flows that changed
        p.process(vec![frame(4, 6000)]);
        let up = p.drain_updates();
        assert_eq!(up.flows.len(), 1);
        assert_eq!(up.flows[0].total_packets, 2);
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
        let up = p.drain_updates();
        assert_eq!(up.dns.len(), 1);
        assert_eq!(up.dns[0].latency, Some(10_000));
        assert!(up.dns_stats.is_some());
        let tcp = up.flows.iter().find(|f| f.protocol == "TCP").unwrap();
        assert_eq!(tcp.domains, vec!["api.github.com"]);
        let dns_flow = up.flows.iter().find(|f| f.protocol == "UDP").unwrap();
        assert!(dns_flow.domains.is_empty());
        assert_eq!(out.packets[1].application_protocol.as_deref(), Some("DNS"));
        assert_eq!(out.packets[1].latency, Some(10_000));
        assert_eq!(out.packets[0].domain.as_deref(), Some("api.github.com"));
        assert_eq!(out.packets[0].latency, None);
        let kinds: Vec<_> = up.events.iter().map(|e| e.kind).collect();
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
        let up = p.drain_updates();
        assert_eq!(out.packets[0].info, "Client Hello (SNI: github.com)");
        assert_eq!(out.packets[0].application_protocol.as_deref(), Some("TLS"));
        assert_eq!(out.packets[1].info, "Server Hello");
        let f = up.flows.iter().find(|f| f.protocol == "TCP").unwrap();
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
        assert!(p.store.lock_recover().is_empty());
        assert!(p.flows.lock_recover().is_empty());
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

        struct Sink<'a>(&'a Pipeline, std::sync::Mutex<Vec<(Processed, Updates)>>);
        impl OfflineSink for Sink<'_> {
            fn progress(&self, _: &Progress) {}
            fn batch(&self, packets: Vec<RawPacket>) {
                let out = self.0.process(packets);
                let up = self.0.drain_updates();
                self.1.lock_recover().push((out, up));
            }
        }
        let p = Pipeline::default();
        let db_path = dir.path().join("session.db");
        p.attach_storage(&db_path, StorageConfig::import(), "e2e.pcap")
            .unwrap();
        let sink = Sink(&p, Default::default());
        let out = offline::run(&path, &AtomicBool::new(false), &sink).unwrap();
        assert_eq!(out.packets, 8);

        let outs = sink.1.lock_recover();
        let packets: Vec<_> = outs.iter().flat_map(|(o, _)| o.packets.iter()).collect();
        assert_eq!(packets.len(), 8);
        assert_eq!(packets[0].info, "Standard query A api.github.com");
        assert_eq!(packets[1].latency, Some(21_000));
        assert_eq!(packets[5].info, "Client Hello (SNI: api.github.com)");
        assert_eq!(packets[6].info, "Server Hello");

        let flows = p.flows.lock_recover().snapshot();
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
            .flat_map(|(_, u)| u.events.iter().map(|e| e.kind))
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

        // Everything that reached the UI was also persisted, and is searchable by indexed fields.
        let status = p.detach_storage().unwrap().unwrap();
        assert_eq!((status.packets_written, status.error), (8, None));
        let db = Database::open(&db_path).unwrap();
        use crate::storage::packets::{PacketQuery, count_packets, query_packets};
        assert_eq!(count_packets(&db, &PacketQuery::default()).unwrap(), 8);
        let tls = query_packets(
            &db,
            &PacketQuery {
                protocol: Some("tls".into()),
                ..Default::default()
            },
        )
        .unwrap();
        // every segment of the port-443 flow is labelled TLS (port heuristic)
        assert_eq!(tls.len(), 6);
        assert!(
            tls.iter()
                .any(|p| p.info == "Client Hello (SNI: api.github.com)")
        );
        let github = PacketQuery {
            domain: Some("API.github.com".into()),
            ..Default::default()
        };
        assert_eq!(count_packets(&db, &github).unwrap(), 3); // DNS query, DNS response, ClientHello
        let flows = crate::storage::flows::query_flows(&db, &Default::default()).unwrap();
        assert_eq!(flows.len(), 2);
        assert_eq!(
            flows[0].tls.as_ref().and_then(|t| t.sni.as_deref()),
            Some("api.github.com")
        );
        assert_eq!(crate::storage::dns::dns_count(&db).unwrap(), 1);
        assert!(crate::storage::events::event_count(&db).unwrap() >= 5);
        assert_eq!(db.meta("source").unwrap().as_deref(), Some("e2e.pcap"));
        assert!(p.storage_status().is_none());
    }

    /// Throughput benchmark. Run with:
    /// `cargo test --release --lib perf_pipeline -- --ignored --nocapture`
    #[test]
    #[ignore = "benchmark"]
    fn perf_pipeline() {
        use crate::testgen::Synth;
        use std::time::Instant;

        fn run(label: &str, n: usize, persist: bool) {
            let dir = tempfile::tempdir().unwrap();
            let p = Pipeline::default();
            if persist {
                p.attach_storage(&dir.path().join("b.db"), StorageConfig::import(), "bench")
                    .unwrap();
            }
            let mut synth = Synth::new(42, 800);
            let batches: Vec<Vec<RawPacket>> = (0..n / 2000).map(|_| synth.batch(2000)).collect();
            let (mut t_proc, mut t_json, mut json_bytes) = (0.0f64, 0.0f64, 0usize);
            for (i, b) in batches.into_iter().enumerate() {
                let t = Instant::now();
                let out = p.process(b);
                t_proc += t.elapsed().as_secs_f64();
                // what the IPC layer does with the result: rows every batch, flows/DNS/events
                // roughly every 250 ms (about 12 batches of 2000 at 100k pkt/s)
                let t = Instant::now();
                json_bytes += serde_json::to_vec(&out.packets).unwrap().len();
                if i % 12 == 11 {
                    let up = p.drain_updates();
                    json_bytes += serde_json::to_vec(&up.flows).unwrap().len();
                    json_bytes += serde_json::to_vec(&up.events).unwrap().len();
                    json_bytes += serde_json::to_vec(&up.dns).unwrap().len();
                }
                t_json += t.elapsed().as_secs_f64();
            }
            let t = Instant::now();
            let snap = p.analytics(false);
            let flows = p.flows.lock_recover().len();
            println!(
                "{label:>28}: analytics() with {flows} flows took {:.1} ms ({} problems)",
                t.elapsed().as_secs_f64() * 1000.0,
                snap.problems.len()
            );
            if persist {
                p.detach_storage().unwrap().unwrap();
            }
            println!(
                "{label:>28}: {n:>8} pkts  process {:>7.0} pkt/s  json {:>7.0} pkt/s  ({:.0} B/pkt on the wire)",
                n as f64 / t_proc,
                n as f64 / t_json,
                json_bytes as f64 / n as f64
            );
        }
        for n in [20_000, 100_000, 500_000, 1_000_000] {
            run("pipeline", n, false);
        }
        run("pipeline + sqlite", 500_000, true);
    }

    /// Where does per-packet time go? Run with `--ignored --nocapture` in release.
    #[test]
    #[ignore = "benchmark"]
    fn perf_breakdown() {
        use crate::testgen::Synth;
        use std::time::Instant;
        let mut synth = Synth::new(42, 800);
        let raws = synth.batch(200_000);
        let n = raws.len() as f64;
        let t = Instant::now();
        let ds: Vec<_> = raws.iter().map(|r| dissect(&r.data)).collect();
        println!(
            "dissect only           {:>9.0} pkt/s",
            n / t.elapsed().as_secs_f64()
        );
        let t = Instant::now();
        let sums: Vec<_> = raws
            .iter()
            .zip(&ds)
            .map(|(r, d)| summarize_dissection(r, d))
            .collect();
        println!(
            "summarize (strings)    {:>9.0} pkt/s",
            n / t.elapsed().as_secs_f64()
        );
        let t = Instant::now();
        let mut eng = FlowEngine::default();
        for (r, d) in raws.iter().zip(&ds) {
            if let Some(i) = FlowInput::from_dissection(r, d) {
                eng.observe_detailed(&i);
            }
        }
        println!(
            "flow engine            {:>9.0} pkt/s",
            n / t.elapsed().as_secs_f64()
        );
        let t = Instant::now();
        let bytes: usize = sums
            .chunks(2000)
            .map(|c| serde_json::to_vec(c).unwrap().len())
            .sum();
        println!(
            "json packets           {:>9.0} pkt/s  ({:.0} B/pkt)",
            n / t.elapsed().as_secs_f64(),
            bytes as f64 / n
        );
        let views = eng.snapshot();
        let t = Instant::now();
        let fb = serde_json::to_vec(&views).unwrap().len();
        println!(
            "json {} flows: {:.1} KB total, {:.0} B/flow, {:.1} ms",
            views.len(),
            fb as f64 / 1024.0,
            fb as f64 / views.len() as f64,
            t.elapsed().as_secs_f64() * 1000.0
        );
    }
}
