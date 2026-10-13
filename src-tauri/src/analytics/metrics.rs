//! Rolling per-second network metrics, rankings and "potential problems".
//!
//! Wording is deliberately careful: anything unusual is reported as a *potential issue*,
//! *unusual* or *worth investigating* — never as an attack or malware verdict.

use std::collections::{HashMap, HashSet, VecDeque};

use serde::Serialize;

use super::dns::DnsStats;
use crate::flows::{Flow, Observed};

/// A day of one-second buckets (~7 MB), enough to chart long offline captures.
const MAX_BUCKETS: usize = 86_400;
/// Points drawn for the whole-capture chart.
const WHOLE_SERIES_POINTS: usize = 300;
/// Longest run of empty seconds filled in explicitly (so a capture gap doesn't allocate hours of zeros).
const MAX_GAP_FILL: i64 = 120;
const TOP_N: usize = 8;

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Bucket {
    /// Unix second of the first second covered.
    pub sec: i64,
    /// Seconds covered by this bucket (1 normally; more when a long capture is downsampled).
    pub span: u32,
    pub packets: u64,
    pub bytes: u64,
    /// Bytes sent by the side that opened each connection / by the side that answered.
    pub bytes_up: u64,
    pub bytes_down: u64,
    pub new_flows: u64,
    /// Distinct flows that carried traffic in this second.
    pub active_flows: u64,
    pub retransmissions: u64,
    pub resets: u64,
    pub duplicate_acks: u64,
    pub zero_windows: u64,
}

impl Default for Bucket {
    fn default() -> Self {
        Self {
            sec: 0,
            span: 1,
            packets: 0,
            bytes: 0,
            bytes_up: 0,
            bytes_down: 0,
            new_flows: 0,
            active_flows: 0,
            retransmissions: 0,
            resets: 0,
            duplicate_acks: 0,
            zero_windows: 0,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct TcpTotals {
    pub packets: u64,
    pub retransmissions: u64,
    pub resets: u64,
    pub duplicate_acks: u64,
    pub zero_windows: u64,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct RankEntry {
    pub key: String,
    pub bytes: u64,
    pub packets: u64,
    pub flows: u64,
}

#[derive(Debug, Clone, Default, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Rankings {
    pub hosts: Vec<RankEntry>,
    pub domains: Vec<RankEntry>,
    pub protocols: Vec<RankEntry>,
    pub ports: Vec<RankEntry>,
    pub talkers: Vec<RankEntry>,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum ProblemLabel {
    PotentialIssue,
    Unusual,
    WorthInvestigating,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Problem {
    /// Stable id so the UI can keep selection/expansion across refreshes.
    pub id: &'static str,
    pub label: ProblemLabel,
    pub title: String,
    pub detail: String,
}

#[derive(Debug, Clone, Default, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct AnalyticsSnapshot {
    /// Most recent buckets, oldest first.
    pub series: Vec<Bucket>,
    pub tcp: TcpTotals,
    pub dns: DnsStats,
    pub rankings: Rankings,
    pub problems: Vec<Problem>,
}

#[derive(Debug, Default)]
pub struct MetricsEngine {
    buckets: VecDeque<Bucket>,
    current_flows: HashSet<u64>,
    tcp: TcpTotals,
}

impl MetricsEngine {
    pub fn new() -> Self {
        Self::default()
    }

    fn bucket_for(&mut self, sec: i64) -> Option<&mut Bucket> {
        let last = self.buckets.back().map(|b| b.sec);
        match last {
            Some(l) if sec == l => {}
            Some(l) if sec > l => {
                if let Some(b) = self.buckets.back_mut() {
                    b.active_flows = self.current_flows.len() as u64;
                }
                self.current_flows.clear();
                let fill_from = if sec - l > MAX_GAP_FILL {
                    sec - MAX_GAP_FILL
                } else {
                    l + 1
                };
                for s in fill_from..=sec {
                    self.buckets.push_back(Bucket {
                        sec: s,
                        ..Default::default()
                    });
                }
                while self.buckets.len() > MAX_BUCKETS {
                    self.buckets.pop_front();
                }
            }
            Some(_) => {
                // Late packet: attribute it to its own second if we still have it.
                return self.buckets.iter_mut().rev().find(|b| b.sec == sec);
            }
            None => self.buckets.push_back(Bucket {
                sec,
                ..Default::default()
            }),
        }
        self.buckets.back_mut()
    }

    /// Account for one packet. `flow` is the flow it belongs to (None for non-IP traffic).
    pub fn observe(&mut self, ts_micros: i64, wire_len: u32, flow: Option<(&Observed, &Flow)>) {
        let sec = ts_micros.div_euclid(1_000_000);
        let mut ids = None;
        let Some(b) = self.bucket_for(sec) else {
            return;
        };
        b.packets += 1;
        b.bytes += u64::from(wire_len);
        if let Some((obs, f)) = flow {
            ids = Some(f.id);
            match obs.direction {
                crate::flows::Direction::AtoB => b.bytes_up += u64::from(wire_len),
                crate::flows::Direction::BtoA => b.bytes_down += u64::from(wire_len),
            }
            b.new_flows += u64::from(obs.is_new);
            let d = |now: u64, before: u64| now.saturating_sub(before);
            b.retransmissions += d(f.retransmissions, obs.retransmissions_before);
            b.resets += d(f.resets, obs.resets_before);
            b.duplicate_acks += d(f.duplicate_acks, obs.duplicate_acks_before);
            b.zero_windows += d(f.zero_windows, obs.zero_windows_before);
            self.tcp.retransmissions += d(f.retransmissions, obs.retransmissions_before);
            self.tcp.resets += d(f.resets, obs.resets_before);
            self.tcp.duplicate_acks += d(f.duplicate_acks, obs.duplicate_acks_before);
            self.tcp.zero_windows += d(f.zero_windows, obs.zero_windows_before);
            if f.proto == crate::flows::Proto::Tcp {
                self.tcp.packets += 1;
            }
        }
        if let Some(id) = ids {
            self.current_flows.insert(id);
        }
    }

    pub fn clear(&mut self) {
        *self = Self::new();
    }

    pub fn series(&self, last: usize) -> Vec<Bucket> {
        let skip = self.buckets.len().saturating_sub(last);
        let mut v: Vec<Bucket> = self.buckets.iter().skip(skip).cloned().collect();
        // The newest bucket is still filling: report its flow count so far.
        if let Some(b) = v.last_mut() {
            b.active_flows = self.current_flows.len() as u64;
        }
        v
    }

    /// The whole history squeezed into at most `max_points` buckets (counts summed, flow gauge maxed).
    pub fn series_whole(&self, max_points: usize) -> Vec<Bucket> {
        let all = self.series(usize::MAX);
        downsample(&all, max_points)
    }

    /// `whole`: chart the entire capture (offline files) instead of the latest few minutes (live).
    pub fn snapshot<'a>(
        &self,
        flows: impl Iterator<Item = &'a Flow>,
        dns: DnsStats,
        dns_failures: &[(String, u32)],
        whole: bool,
    ) -> AnalyticsSnapshot {
        let rankings = rank(flows);
        // Problem detection always looks at recent raw seconds, whatever is charted.
        let recent = self.series(300);
        let problems = detect_problems(&self.tcp, &recent, &dns, dns_failures, &rankings);
        let series = if whole {
            self.series_whole(WHOLE_SERIES_POINTS)
        } else {
            recent
        };
        AnalyticsSnapshot {
            series,
            tcp: self.tcp.clone(),
            dns,
            rankings,
            problems,
        }
    }
}

fn downsample(all: &[Bucket], max_points: usize) -> Vec<Bucket> {
    let max_points = max_points.max(1);
    if all.len() <= max_points {
        return all.to_vec();
    }
    let k = all.len().div_ceil(max_points);
    all.chunks(k)
        .map(|chunk| {
            let mut b = Bucket {
                sec: chunk[0].sec,
                span: 0,
                ..Default::default()
            };
            for c in chunk {
                b.span += c.span;
                b.packets += c.packets;
                b.bytes += c.bytes;
                b.bytes_up += c.bytes_up;
                b.bytes_down += c.bytes_down;
                b.new_flows += c.new_flows;
                b.active_flows = b.active_flows.max(c.active_flows);
                b.retransmissions += c.retransmissions;
                b.resets += c.resets;
                b.duplicate_acks += c.duplicate_acks;
                b.zero_windows += c.zero_windows;
            }
            b
        })
        .collect()
}

fn top(map: HashMap<String, RankEntry>) -> Vec<RankEntry> {
    let mut v: Vec<RankEntry> = map.into_values().collect();
    v.sort_by(|a, b| b.bytes.cmp(&a.bytes).then_with(|| a.key.cmp(&b.key)));
    v.truncate(TOP_N);
    v
}

fn bump(map: &mut HashMap<String, RankEntry>, key: String, bytes: u64, packets: u64) {
    let e = map.entry(key.clone()).or_insert(RankEntry {
        key,
        bytes: 0,
        packets: 0,
        flows: 0,
    });
    e.bytes += bytes;
    e.packets += packets;
    e.flows += 1;
}

fn protocol_label(f: &Flow) -> String {
    if f.tls.is_some() {
        return "TLS".into();
    }
    // Same port heuristics as the flow list, so the two screens agree.
    crate::flows::FlowView::of(f)
        .application_protocol
        .unwrap_or_else(|| f.proto.name())
}

pub fn rank<'a>(flows: impl Iterator<Item = &'a Flow>) -> Rankings {
    let (mut hosts, mut domains, mut protocols, mut ports, mut talkers) = (
        HashMap::new(),
        HashMap::new(),
        HashMap::new(),
        HashMap::new(),
        HashMap::new(),
    );
    for f in flows {
        let (bytes, packets) = (f.total_bytes(), f.total_packets());
        bump(&mut hosts, f.endpoint_b.ip.to_string(), bytes, packets);
        if let Some(d) = f
            .tls
            .as_ref()
            .and_then(|t| t.sni.clone())
            .or_else(|| f.domains.first().cloned())
        {
            bump(&mut domains, d, bytes, packets);
        }
        bump(&mut protocols, protocol_label(f), bytes, packets);
        if f.endpoint_b.port > 0 {
            bump(
                &mut ports,
                format!("{}/{}", f.endpoint_b.port, f.proto.name()),
                bytes,
                packets,
            );
        }
        bump(
            &mut talkers,
            f.endpoint_a.ip.to_string(),
            f.bytes_a_to_b,
            f.packets_a_to_b,
        );
        bump(
            &mut talkers,
            f.endpoint_b.ip.to_string(),
            f.bytes_b_to_a,
            f.packets_b_to_a,
        );
    }
    Rankings {
        hosts: top(hosts),
        domains: top(domains),
        protocols: top(protocols),
        ports: top(ports),
        talkers: top(talkers),
    }
}

fn ms(micros: i64) -> String {
    format!("{:.0} ms", micros as f64 / 1000.0)
}

pub fn detect_problems(
    tcp: &TcpTotals,
    series: &[Bucket],
    dns: &DnsStats,
    dns_failures: &[(String, u32)],
    ranks: &Rankings,
) -> Vec<Problem> {
    let mut out = Vec::new();

    if let Some(p95) = dns.p95_latency.filter(|p| *p > 100_000) {
        out.push(Problem {
            id: "dns-latency",
            label: ProblemLabel::PotentialIssue,
            title: "High DNS latency".into(),
            detail: format!("95% of lookups finished within {} (average {}). Slow resolvers delay every new connection.", ms(p95), dns.avg_latency.map_or("unknown".into(), ms)),
        });
    }

    if tcp.packets >= 100 && tcp.retransmissions >= 5 {
        let pct = tcp.retransmissions as f64 / tcp.packets as f64 * 100.0;
        if pct >= 1.0 {
            out.push(Problem {
                id: "retransmissions",
                label: ProblemLabel::PotentialIssue,
                title: "High retransmission rate".into(),
                detail: format!("{} of {} TCP packets ({pct:.1}%) were retransmissions. This can come from loss or congestion, or from where the capture was taken.", tcp.retransmissions, tcp.packets),
            });
        }
    }

    // Resets clustered in time: 10+ within any 10-second window.
    let mut worst = 0;
    for w in 0..series.len() {
        let end = (w + 10).min(series.len());
        worst = worst.max(series[w..end].iter().map(|b| b.resets).sum::<u64>());
    }
    if worst >= 10 {
        out.push(Problem { id: "reset-burst", label: ProblemLabel::Unusual, title: "Connection reset burst".into(), detail: format!("{worst} connections were reset within 10 seconds. Worth checking whether a service or firewall is rejecting connections.") });
    }

    let total: u64 = ranks.talkers.iter().map(|t| t.bytes).sum();
    if let Some(top) = ranks.talkers.first()
        && total >= 1_000_000
    {
        let share = top.bytes as f64 / total as f64;
        // `total` only covers the top talkers, so this is a conservative lower bound on the share.
        if share >= 0.7 {
            out.push(Problem {
                id: "dominant-endpoint",
                label: ProblemLabel::WorthInvestigating,
                title: "High traffic from one endpoint".into(),
                detail: format!(
                    "{} sent {:.0}% of the data among the busiest senders.",
                    top.key,
                    share * 100.0
                ),
            });
        }
    }

    let mut repeated: Vec<(&str, u32)> = dns_failures
        .iter()
        .filter(|(_, n)| *n >= 3)
        .map(|(d, n)| (d.as_str(), *n))
        .collect();
    repeated.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(b.0)));
    if let Some((name, n)) = repeated.first() {
        out.push(Problem {
            id: "dns-failures",
            label: ProblemLabel::WorthInvestigating,
            title: "Repeated failed DNS resolutions".into(),
            detail: format!(
                "{name} failed to resolve {n} times{}.",
                if repeated.len() > 1 {
                    format!(
                        " (and {} other name{})",
                        repeated.len() - 1,
                        if repeated.len() == 2 { "" } else { "s" }
                    )
                } else {
                    String::new()
                }
            ),
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::flows::{Endpoint, FlowEngine, FlowInput, Proto, TcpInfo};
    use crate::protocols::tcp::{ACK, RST};

    const SEC: i64 = 1_000_000;

    fn udp(ts: i64, sport: u16, len: u32) -> FlowInput {
        FlowInput {
            ts_micros: ts,
            src: Endpoint {
                ip: "192.168.1.20".parse().unwrap(),
                port: sport,
            },
            dst: Endpoint {
                ip: "8.8.8.8".parse().unwrap(),
                port: 53,
            },
            proto: Proto::Udp,
            wire_len: len,
            tcp: None,
        }
    }

    fn tcp(ts: i64, port: u16, flags: u16, seq: u32, len: u32) -> FlowInput {
        FlowInput {
            ts_micros: ts,
            src: Endpoint {
                ip: "192.168.1.20".parse().unwrap(),
                port,
            },
            dst: Endpoint {
                ip: "140.82.121.4".parse().unwrap(),
                port: 443,
            },
            proto: Proto::Tcp,
            wire_len: 54 + len,
            tcp: Some(TcpInfo {
                seq,
                ack: 1,
                flags,
                window: 1000,
                payload_len: len,
            }),
        }
    }

    fn feed(m: &mut MetricsEngine, e: &mut FlowEngine, input: FlowInput) {
        let obs = e.observe_detailed(&input);
        m.observe(
            input.ts_micros,
            input.wire_len,
            Some((&obs, e.get(obs.id).unwrap())),
        );
    }

    #[test]
    fn buckets_count_per_second_and_new_flows() {
        let (mut m, mut e) = (MetricsEngine::new(), FlowEngine::default());
        feed(&mut m, &mut e, udp(10 * SEC, 1000, 100));
        feed(&mut m, &mut e, udp(10 * SEC + 5, 1000, 100));
        feed(&mut m, &mut e, udp(10 * SEC + 6, 2000, 50));
        feed(&mut m, &mut e, udp(11 * SEC, 1000, 100));
        let s = m.series(10);
        assert_eq!(s.len(), 2);
        assert_eq!(
            (
                s[0].sec,
                s[0].packets,
                s[0].bytes,
                s[0].new_flows,
                s[0].active_flows
            ),
            (10, 3, 250, 2, 2)
        );
        assert_eq!(
            (s[1].sec, s[1].packets, s[1].new_flows, s[1].active_flows),
            (11, 1, 0, 1)
        );
    }

    #[test]
    fn upload_and_download_follow_the_connection_direction() {
        let (mut m, mut e) = (MetricsEngine::new(), FlowEngine::default());
        feed(&mut m, &mut e, udp(SEC, 1000, 100)); // client → server
        let mut reply = udp(SEC + 1, 1000, 200);
        std::mem::swap(&mut reply.src, &mut reply.dst); // server → client
        feed(&mut m, &mut e, reply);
        let b = &m.series(5)[0];
        assert_eq!((b.bytes, b.bytes_up, b.bytes_down), (300, 100, 200));
    }

    #[test]
    fn gaps_are_filled_with_zero_buckets_but_bounded() {
        let (mut m, mut e) = (MetricsEngine::new(), FlowEngine::default());
        feed(&mut m, &mut e, udp(10 * SEC, 1000, 1));
        feed(&mut m, &mut e, udp(14 * SEC, 1000, 1));
        let s = m.series(100);
        assert_eq!(
            s.iter().map(|b| (b.sec, b.packets)).collect::<Vec<_>>(),
            vec![(10, 1), (11, 0), (12, 0), (13, 0), (14, 1)]
        );
        feed(&mut m, &mut e, udp(100_000 * SEC, 1000, 1));
        assert!(m.series(10_000).len() <= MAX_GAP_FILL as usize + 6);
    }

    #[test]
    fn late_packets_land_in_their_own_second() {
        let (mut m, mut e) = (MetricsEngine::new(), FlowEngine::default());
        feed(&mut m, &mut e, udp(10 * SEC, 1000, 1));
        feed(&mut m, &mut e, udp(12 * SEC, 1000, 1));
        feed(&mut m, &mut e, udp(10 * SEC + 5, 1000, 1));
        assert_eq!(m.series(10)[0].packets, 2);
        feed(&mut m, &mut e, udp(SEC, 1000, 1)); // older than anything retained: ignored, no panic
    }

    #[test]
    fn tcp_health_counters_follow_the_flow_engine() {
        let (mut m, mut e) = (MetricsEngine::new(), FlowEngine::default());
        feed(&mut m, &mut e, tcp(SEC, 40000, ACK, 1000, 100));
        feed(&mut m, &mut e, tcp(SEC + 1, 40000, ACK, 1000, 100)); // retransmission
        feed(&mut m, &mut e, tcp(SEC + 2, 40000, RST, 1100, 0));
        let snap = m.snapshot(e.snapshot_flows(), DnsStats::default(), &[], false);
        assert_eq!(
            (snap.tcp.packets, snap.tcp.retransmissions, snap.tcp.resets),
            (3, 1, 1)
        );
        assert_eq!(snap.series[0].retransmissions, 1);
    }

    #[test]
    fn long_captures_are_downsampled_without_losing_counts() {
        let (mut m, mut e) = (MetricsEngine::new(), FlowEngine::default());
        for s in 0..1000 {
            feed(&mut m, &mut e, udp(s * SEC, 1000 + (s % 3) as u16, 100));
        }
        let whole = m.series_whole(100);
        assert!(whole.len() <= 100);
        assert_eq!(whole.iter().map(|b| b.packets).sum::<u64>(), 1000);
        assert_eq!(whole.iter().map(|b| u64::from(b.span)).sum::<u64>(), 1000);
        assert_eq!(whole[0].sec, 0);
        let snap = m.snapshot(e.snapshot_flows(), DnsStats::default(), &[], true);
        assert!(snap.series.len() <= WHOLE_SERIES_POINTS);
        assert_eq!(
            m.snapshot(e.snapshot_flows(), DnsStats::default(), &[], false)
                .series
                .len(),
            300
        );
        assert_eq!(m.series_whole(5000).len(), 1000); // small enough: untouched
    }

    #[test]
    fn rankings_cover_hosts_domains_protocols_ports_and_talkers() {
        let (mut m, mut e) = (MetricsEngine::new(), FlowEngine::default());
        feed(&mut m, &mut e, tcp(SEC, 40000, ACK, 1, 1000));
        feed(&mut m, &mut e, udp(SEC, 5000, 100));
        let id = e.snapshot()[0].id;
        e.add_domains(id, &["github.com".into()]);
        let r = rank(e.snapshot_flows());
        assert_eq!(r.hosts[0].key, "140.82.121.4");
        assert_eq!(r.domains[0].key, "github.com");
        assert_eq!(r.protocols[0].key, "TLS"); // port 443
        assert_eq!(r.protocols[1].key, "DNS");
        assert_eq!(r.ports[0].key, "443/TCP");
        assert_eq!(r.talkers[0].key, "192.168.1.20");
        assert!(r.hosts.len() <= TOP_N);
    }

    #[test]
    fn dns_latency_problem_uses_careful_wording() {
        let dns = DnsStats {
            p95_latency: Some(250_000),
            avg_latency: Some(80_000),
            ..Default::default()
        };
        let p = detect_problems(&TcpTotals::default(), &[], &dns, &[], &Rankings::default());
        assert_eq!(p.len(), 1);
        assert_eq!(
            (p[0].id, p[0].label),
            ("dns-latency", ProblemLabel::PotentialIssue)
        );
        assert!(p[0].detail.contains("250 ms"));
        assert!(
            detect_problems(
                &TcpTotals::default(),
                &[],
                &DnsStats {
                    p95_latency: Some(50_000),
                    ..Default::default()
                },
                &[],
                &Rankings::default()
            )
            .is_empty()
        );
    }

    #[test]
    fn retransmission_rate_needs_volume_and_threshold() {
        let few = TcpTotals {
            packets: 50,
            retransmissions: 10,
            ..Default::default()
        };
        assert!(
            detect_problems(&few, &[], &DnsStats::default(), &[], &Rankings::default()).is_empty()
        );
        let low = TcpTotals {
            packets: 10_000,
            retransmissions: 6,
            ..Default::default()
        };
        assert!(
            detect_problems(&low, &[], &DnsStats::default(), &[], &Rankings::default()).is_empty()
        );
        let high = TcpTotals {
            packets: 1000,
            retransmissions: 30,
            ..Default::default()
        };
        let p = detect_problems(&high, &[], &DnsStats::default(), &[], &Rankings::default());
        assert_eq!(p[0].id, "retransmissions");
        assert!(p[0].detail.contains("3.0%"));
    }

    #[test]
    fn reset_bursts_are_windowed() {
        let bucket = |sec, resets| Bucket {
            sec,
            resets,
            ..Default::default()
        };
        let spread: Vec<Bucket> = (0..40)
            .map(|s| bucket(s, if s % 10 == 0 { 3 } else { 0 }))
            .collect();
        assert!(
            detect_problems(
                &TcpTotals::default(),
                &spread,
                &DnsStats::default(),
                &[],
                &Rankings::default()
            )
            .is_empty()
        );
        let burst: Vec<Bucket> = (0..40)
            .map(|s| bucket(s, if (20..25).contains(&s) { 3 } else { 0 }))
            .collect();
        let p = detect_problems(
            &TcpTotals::default(),
            &burst,
            &DnsStats::default(),
            &[],
            &Rankings::default(),
        );
        assert_eq!(
            (p[0].id, p[0].label),
            ("reset-burst", ProblemLabel::Unusual)
        );
    }

    #[test]
    fn dominant_sender_and_repeated_dns_failures() {
        let ranks = Rankings {
            talkers: vec![
                RankEntry {
                    key: "10.0.0.9".into(),
                    bytes: 9_000_000,
                    packets: 1,
                    flows: 1,
                },
                RankEntry {
                    key: "10.0.0.2".into(),
                    bytes: 500_000,
                    packets: 1,
                    flows: 1,
                },
            ],
            ..Default::default()
        };
        let fails = |n: u32| vec![("nope.invalid".to_string(), n)];
        let p = detect_problems(
            &TcpTotals::default(),
            &[],
            &DnsStats::default(),
            &fails(3),
            &ranks,
        );
        let ids: Vec<_> = p.iter().map(|x| x.id).collect();
        assert_eq!(ids, vec!["dominant-endpoint", "dns-failures"]);
        assert!(
            p[1].detail
                .starts_with("nope.invalid failed to resolve 3 times")
        );
        for problem in &p {
            let text = format!("{} {}", problem.title, problem.detail).to_lowercase();
            assert!(
                !text.contains("attack") && !text.contains("malware"),
                "{text}"
            );
        }
        // two failures are not "repeated"
        assert!(
            detect_problems(
                &TcpTotals::default(),
                &[],
                &DnsStats::default(),
                &fails(2),
                &Rankings::default()
            )
            .is_empty()
        );
    }
}
