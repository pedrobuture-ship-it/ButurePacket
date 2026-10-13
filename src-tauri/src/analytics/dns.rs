//! Stateful DNS correlation: pairs queries with responses, measures latency and learns
//! which domains were *recently* seen resolving to which addresses.
//!
//! The domain↔IP relation is temporal and many-to-many (CDNs, shared hosting), so it is only
//! ever offered as a "likely" hint and never as an exclusive fact.

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::IpAddr;

use serde::Serialize;

use crate::protocols::dns::{self, Dns, RCODE_NOERROR, RData};

const TIMEOUT_MICROS: i64 = 5_000_000;
const SWEEP_INTERVAL_MICROS: i64 = 1_000_000;
const MAX_TRANSACTIONS: usize = 100_000;
const MAX_RELATIONS: usize = 200_000;
const MAX_PER_KEY: usize = 32;
const MAX_LATENCIES: usize = 200_000;
const MAX_DOMAINS_TRACKED: usize = 200_000;

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DnsAnswer {
    pub name: String,
    pub record_type: String,
    pub data: String,
    pub ttl: u32,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum DnsStatus {
    Pending,
    Ok,
    /// Responded with an error code (NXDOMAIN, SERVFAIL, ...).
    Failed,
    /// No response within the timeout.
    Timeout,
}

#[derive(Debug, Clone)]
struct Transaction {
    id: u64,
    flow_id: Option<u64>,
    client: IpAddr,
    resolver: IpAddr,
    txid: u16,
    name: String,
    qtype: String,
    query_ts: Option<i64>,
    response_ts: Option<i64>,
    latency: Option<i64>,
    rcode: Option<u8>,
    answers: Vec<DnsAnswer>,
    timed_out: bool,
}

impl Transaction {
    fn status(&self) -> DnsStatus {
        match (self.rcode, self.timed_out) {
            (Some(RCODE_NOERROR), _) => DnsStatus::Ok,
            (Some(_), _) => DnsStatus::Failed,
            (None, true) => DnsStatus::Timeout,
            (None, false) => DnsStatus::Pending,
        }
    }
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DnsTransactionView {
    pub id: u64,
    pub flow_id: Option<u64>,
    pub client: IpAddr,
    pub resolver: IpAddr,
    pub transaction_id: u16,
    pub query_name: String,
    pub query_type: String,
    pub query_at: Option<i64>,
    pub response_at: Option<i64>,
    /// Microseconds between query and response.
    pub latency: Option<i64>,
    pub response_code: Option<String>,
    pub status: DnsStatus,
    pub answers: Vec<DnsAnswer>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ResolverStat {
    pub ip: IpAddr,
    pub queries: u64,
    pub failures: u64,
    pub avg_latency: Option<i64>,
}

#[derive(Debug, Clone, Default, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct DnsStats {
    pub queries: u64,
    pub responses: u64,
    pub failures: u64,
    pub unique_domains: usize,
    pub avg_latency: Option<i64>,
    pub p95_latency: Option<i64>,
    pub resolvers: Vec<ResolverStat>,
}

#[derive(Debug, Default)]
struct ResolverAcc {
    queries: u64,
    failures: u64,
    latency_sum: i64,
    latency_n: u64,
}

#[derive(Debug, Clone)]
struct DomainObs {
    domain: String,
    first_seen: i64,
    last_seen: i64,
}

#[derive(Debug)]
pub struct DnsTracker {
    transactions: VecDeque<Transaction>,
    first_id: u64,
    next_id: u64,
    /// (client, client port, resolver, txid) → transaction id awaiting a response.
    pending: HashMap<(IpAddr, u16, IpAddr, u16), u64>,
    dirty: HashSet<u64>,
    ip_domains: HashMap<IpAddr, Vec<DomainObs>>,
    domains_seen: HashSet<String>,
    latencies: Vec<i64>,
    resolvers: HashMap<IpAddr, ResolverAcc>,
    queries: u64,
    responses: u64,
    failures: u64,
    last_ts: i64,
    last_sweep: i64,
    stats_dirty: bool,
}

impl Default for DnsTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl DnsTracker {
    pub fn new() -> Self {
        Self {
            transactions: VecDeque::new(),
            first_id: 1,
            next_id: 1,
            pending: HashMap::new(),
            dirty: HashSet::new(),
            ip_domains: HashMap::new(),
            domains_seen: HashSet::new(),
            latencies: Vec::new(),
            resolvers: HashMap::new(),
            queries: 0,
            responses: 0,
            failures: 0,
            last_ts: 0,
            last_sweep: 0,
            stats_dirty: false,
        }
    }

    fn txn_mut(&mut self, id: u64) -> Option<&mut Transaction> {
        let idx = usize::try_from(id.checked_sub(self.first_id)?).ok()?;
        self.transactions.get_mut(idx)
    }

    fn push(&mut self, t: Transaction) {
        self.dirty.insert(t.id);
        self.transactions.push_back(t);
        while self.transactions.len() > MAX_TRANSACTIONS {
            if let Some(old) = self.transactions.pop_front() {
                self.first_id = old.id + 1;
                self.dirty.remove(&old.id);
                self.pending.retain(|_, id| *id != old.id);
            }
        }
    }

    /// Records one DNS message. For a response that matches a captured query, returns the latency.
    #[allow(clippy::too_many_arguments)]
    pub fn observe(
        &mut self,
        ts: i64,
        src: IpAddr,
        sport: u16,
        dst: IpAddr,
        dport: u16,
        flow_id: Option<u64>,
        msg: &Dns,
    ) -> Option<i64> {
        self.last_ts = self.last_ts.max(ts);
        let mut latency = None;
        if !msg.is_response {
            self.on_query(ts, src, sport, dst, flow_id, msg);
        } else {
            latency = self.on_response(ts, src, dst, dport, flow_id, msg);
        }
        if ts - self.last_sweep >= SWEEP_INTERVAL_MICROS {
            self.sweep(ts);
        }
        latency
    }

    fn on_query(
        &mut self,
        ts: i64,
        client: IpAddr,
        cport: u16,
        resolver: IpAddr,
        flow_id: Option<u64>,
        msg: &Dns,
    ) {
        let Some(q) = msg.questions.first() else {
            return;
        };
        let key = (client, cport, resolver, msg.id);
        if let Some(&existing) = self.pending.get(&key) {
            // Same transaction asked again: a retry, not a new query.
            if self.txn_mut(existing).is_some_and(|t| t.name == q.name) {
                return;
            }
        }
        let id = self.next_id;
        self.next_id += 1;
        self.queries += 1;
        self.resolvers.entry(resolver).or_default().queries += 1;
        if self.domains_seen.len() < MAX_DOMAINS_TRACKED {
            self.domains_seen.insert(q.name.to_lowercase());
        }
        self.pending.insert(key, id);
        self.stats_dirty = true;
        self.push(Transaction {
            id,
            flow_id,
            client,
            resolver,
            txid: msg.id,
            name: q.name.clone(),
            qtype: dns::type_name(q.qtype),
            query_ts: Some(ts),
            response_ts: None,
            latency: None,
            rcode: None,
            answers: vec![],
            timed_out: false,
        });
    }

    fn on_response(
        &mut self,
        ts: i64,
        resolver: IpAddr,
        client: IpAddr,
        cport: u16,
        flow_id: Option<u64>,
        msg: &Dns,
    ) -> Option<i64> {
        let answers: Vec<DnsAnswer> = msg
            .answers
            .iter()
            .map(|a| DnsAnswer {
                name: a.name.clone(),
                record_type: dns::type_name(a.rtype),
                data: a.data.text(),
                ttl: a.ttl,
            })
            .collect();
        let qname = msg.questions.first().map(|q| q.name.clone());
        let key = (client, cport, resolver, msg.id);
        let matched = self.pending.remove(&key);
        self.responses += 1;
        self.stats_dirty = true;
        let failed = msg.rcode != RCODE_NOERROR;
        let acc = self.resolvers.entry(resolver).or_default();
        if failed {
            acc.failures += 1;
            self.failures += 1;
        }

        let mut latency = None;
        match matched.and_then(|id| self.txn_mut(id).map(|t| (id, t))) {
            Some((id, t)) => {
                t.response_ts = Some(ts);
                t.rcode = Some(msg.rcode);
                t.answers = answers;
                t.timed_out = false;
                latency = t.query_ts.map(|q| (ts - q).max(0));
                t.latency = latency;
                self.dirty.insert(id);
            }
            None => {
                // The query was not captured (or was evicted): record the response on its own.
                let id = self.next_id;
                self.next_id += 1;
                self.push(Transaction {
                    id,
                    flow_id,
                    client,
                    resolver,
                    txid: msg.id,
                    name: qname.clone().unwrap_or_else(|| ".".into()),
                    qtype: msg
                        .questions
                        .first()
                        .map(|q| dns::type_name(q.qtype))
                        .unwrap_or_default(),
                    query_ts: None,
                    response_ts: Some(ts),
                    latency: None,
                    rcode: Some(msg.rcode),
                    answers,
                    timed_out: false,
                });
            }
        }
        if let Some(l) = latency {
            if self.latencies.len() >= MAX_LATENCIES {
                self.latencies.drain(..MAX_LATENCIES / 10);
            }
            self.latencies.push(l);
            let acc = self.resolvers.entry(resolver).or_default();
            acc.latency_sum += l;
            acc.latency_n += 1;
        }

        if !failed {
            let asked = qname.as_deref();
            for a in &msg.answers {
                let ip: IpAddr = match &a.data {
                    RData::A(v4) => (*v4).into(),
                    RData::Aaaa(v6) => (*v6).into(),
                    _ => continue,
                };
                // Attribute to the name that was asked *and* to the record owner (CNAME target).
                if let Some(q) = asked {
                    self.learn(ip, q, ts);
                }
                if asked.is_none_or(|q| !q.eq_ignore_ascii_case(&a.name)) {
                    self.learn(ip, &a.name, ts);
                }
            }
        }
        latency
    }

    fn learn(&mut self, ip: IpAddr, domain: &str, ts: i64) {
        if !self.ip_domains.contains_key(&ip) && self.ip_domains.len() >= MAX_RELATIONS {
            return;
        }
        let domain = domain.trim_end_matches('.').to_lowercase();
        if domain.is_empty() {
            return;
        }
        let list = self.ip_domains.entry(ip).or_default();
        match list.iter_mut().find(|o| o.domain == domain) {
            Some(o) => o.last_seen = ts,
            None => {
                if list.len() >= MAX_PER_KEY {
                    list.remove(0);
                }
                list.push(DomainObs {
                    domain,
                    first_seen: ts,
                    last_seen: ts,
                });
            }
        }
    }

    /// Domains that were recently observed resolving to `ip`, most recent first.
    /// Only answers seen at or before `at` are considered. These are hints, not facts.
    pub fn likely_domains(&self, ip: IpAddr, at: i64) -> Vec<String> {
        let Some(list) = self.ip_domains.get(&ip) else {
            return vec![];
        };
        let mut seen: Vec<&DomainObs> = list.iter().filter(|o| o.first_seen <= at).collect();
        seen.sort_by_key(|o| std::cmp::Reverse(o.last_seen));
        seen.iter().take(3).map(|o| o.domain.clone()).collect()
    }

    /// Every address a domain was seen resolving to (case-insensitive).
    pub fn ips_for_domain(&self, domain: &str) -> Vec<IpAddr> {
        let d = domain.trim_end_matches('.').to_lowercase();
        let mut v: Vec<IpAddr> = self
            .ip_domains
            .iter()
            .filter(|(_, list)| list.iter().any(|o| o.domain == d))
            .map(|(ip, _)| *ip)
            .collect();
        v.sort();
        v
    }

    fn sweep(&mut self, now: i64) {
        self.last_sweep = now;
        let expired: Vec<_> = self
            .pending
            .iter()
            .filter(|(_, id)| {
                self.txn_ref(**id)
                    .is_some_and(|t| t.query_ts.is_some_and(|q| now - q > TIMEOUT_MICROS))
            })
            .map(|(k, id)| (*k, *id))
            .collect();
        for (key, id) in expired {
            self.pending.remove(&key);
            if let Some(t) = self.txn_mut(id) {
                t.timed_out = true;
                let resolver = t.resolver;
                self.dirty.insert(id);
                self.failures += 1;
                self.resolvers.entry(resolver).or_default().failures += 1;
                self.stats_dirty = true;
            }
        }
    }

    fn txn_ref(&self, id: u64) -> Option<&Transaction> {
        let idx = usize::try_from(id.checked_sub(self.first_id)?).ok()?;
        self.transactions.get(idx)
    }

    fn view(t: &Transaction) -> DnsTransactionView {
        DnsTransactionView {
            id: t.id,
            flow_id: t.flow_id,
            client: t.client,
            resolver: t.resolver,
            transaction_id: t.txid,
            query_name: t.name.clone(),
            query_type: t.qtype.clone(),
            query_at: t.query_ts,
            response_at: t.response_ts,
            latency: t.latency,
            response_code: t.rcode.map(dns::rcode_name),
            status: t.status(),
            answers: t.answers.clone(),
        }
    }

    pub fn take_changed(&mut self) -> Vec<DnsTransactionView> {
        let mut ids: Vec<u64> = self.dirty.drain().collect();
        ids.sort_unstable();
        ids.iter()
            .filter_map(|id| self.txn_ref(*id))
            .map(Self::view)
            .collect()
    }

    /// Statistics if anything changed since the last call.
    pub fn take_stats_if_changed(&mut self) -> Option<DnsStats> {
        if !std::mem::take(&mut self.stats_dirty) {
            return None;
        }
        Some(self.stats())
    }

    /// Domains whose lookups failed or timed out, with how many times, most frequent first.
    pub fn failed_domains(&self) -> Vec<(String, u32)> {
        let mut counts: HashMap<&str, u32> = HashMap::new();
        for t in &self.transactions {
            if matches!(t.status(), DnsStatus::Failed | DnsStatus::Timeout) {
                *counts.entry(t.name.as_str()).or_default() += 1;
            }
        }
        let mut v: Vec<(String, u32)> = counts
            .into_iter()
            .map(|(k, n)| (k.to_string(), n))
            .collect();
        v.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        v
    }

    pub fn snapshot(&self) -> Vec<DnsTransactionView> {
        self.transactions.iter().map(Self::view).collect()
    }

    pub fn stats(&self) -> DnsStats {
        let mut sorted = self.latencies.clone();
        let (avg, p95) = if sorted.is_empty() {
            (None, None)
        } else {
            let avg = sorted.iter().sum::<i64>() / sorted.len() as i64;
            // Nearest-rank percentile.
            let rank = ((sorted.len() as f64) * 0.95).ceil() as usize;
            let idx = rank.clamp(1, sorted.len()) - 1;
            let (_, v, _) = sorted.select_nth_unstable(idx);
            (Some(avg), Some(*v))
        };
        let mut resolvers: Vec<ResolverStat> = self
            .resolvers
            .iter()
            .map(|(ip, a)| ResolverStat {
                ip: *ip,
                queries: a.queries,
                failures: a.failures,
                avg_latency: (a.latency_n > 0).then(|| a.latency_sum / a.latency_n as i64),
            })
            .collect();
        resolvers.sort_by(|a, b| b.queries.cmp(&a.queries).then(a.ip.cmp(&b.ip)));
        DnsStats {
            queries: self.queries,
            responses: self.responses,
            failures: self.failures,
            unique_domains: self.domains_seen.len(),
            avg_latency: avg,
            p95_latency: p95,
            resolvers,
        }
    }

    pub fn clear(&mut self) {
        *self = Self::new();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocols::dns::{
        parse,
        tests::{query, response},
    };

    const CLIENT: &str = "192.168.1.20";
    const RESOLVER: &str = "8.8.8.8";
    const MS: i64 = 1000;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn send_query(t: &mut DnsTracker, ts: i64, id: u16, name: &str) {
        t.observe(
            ts,
            ip(CLIENT),
            55000,
            ip(RESOLVER),
            53,
            None,
            &parse(&query(id, name, 1)).unwrap(),
        );
    }

    fn send_response(
        t: &mut DnsTracker,
        ts: i64,
        id: u16,
        name: &str,
        addrs: &[[u8; 4]],
        rcode: u8,
    ) {
        t.observe(
            ts,
            ip(RESOLVER),
            53,
            ip(CLIENT),
            55000,
            None,
            &parse(&response(id, name, None, addrs, 300, rcode)).unwrap(),
        );
    }

    #[test]
    fn pairs_query_and_response_with_latency() {
        let mut t = DnsTracker::new();
        send_query(&mut t, 1_000_000, 7, "api.github.com");
        send_response(
            &mut t,
            1_021_000,
            7,
            "api.github.com",
            &[[140, 82, 121, 5]],
            0,
        );
        let v = t.take_changed();
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].latency, Some(21 * MS));
        assert_eq!(v[0].status, DnsStatus::Ok);
        assert_eq!(v[0].query_name, "api.github.com");
        assert_eq!(v[0].answers[0].data, "140.82.121.5");
        assert_eq!(v[0].answers[0].ttl, 300);
        assert_eq!(v[0].response_code.as_deref(), Some("NOERROR"));
    }

    #[test]
    fn responses_only_match_the_right_transaction() {
        let mut t = DnsTracker::new();
        send_query(&mut t, 0, 1, "a.example");
        send_query(&mut t, 10, 2, "b.example");
        send_response(&mut t, 5000, 2, "b.example", &[[2, 2, 2, 2]], 0);
        let v = t.snapshot();
        assert_eq!(
            (v[0].status, v[1].status),
            (DnsStatus::Pending, DnsStatus::Ok)
        );
        assert_eq!(v[1].latency, Some(4990));
    }

    #[test]
    fn duplicate_queries_are_retries() {
        let mut t = DnsTracker::new();
        send_query(&mut t, 0, 1, "a.example");
        send_query(&mut t, 1_000_000, 1, "a.example");
        assert_eq!(t.snapshot().len(), 1);
        assert_eq!(t.stats().queries, 1);
        // latency is measured from the first attempt
        send_response(&mut t, 1_500_000, 1, "a.example", &[[1, 1, 1, 1]], 0);
        assert_eq!(t.snapshot()[0].latency, Some(1_500_000));
    }

    #[test]
    fn failures_and_timeouts_are_counted() {
        let mut t = DnsTracker::new();
        send_query(&mut t, 0, 1, "nope.invalid");
        send_response(&mut t, 10 * MS, 1, "nope.invalid", &[], 3);
        send_query(&mut t, 20 * MS, 2, "slow.example");
        assert_eq!(t.stats().failures, 1);
        // time passes: any later DNS traffic triggers the sweep
        send_query(&mut t, 7_000_000, 3, "later.example");
        let s = t.stats();
        assert_eq!(s.failures, 2);
        let v = t.snapshot();
        assert_eq!(
            (v[0].status, v[1].status, v[2].status),
            (DnsStatus::Failed, DnsStatus::Timeout, DnsStatus::Pending)
        );
        assert_eq!(v[0].response_code.as_deref(), Some("NXDOMAIN"));
    }

    #[test]
    fn unmatched_response_is_recorded_without_latency() {
        let mut t = DnsTracker::new();
        send_response(&mut t, 100, 9, "orphan.example", &[[3, 3, 3, 3]], 0);
        let v = t.snapshot();
        assert_eq!(v.len(), 1);
        assert_eq!((v[0].latency, v[0].query_at), (None, None));
        assert_eq!(t.stats().avg_latency, None);
    }

    #[test]
    fn domain_ip_relations_are_temporal_and_non_exclusive() {
        let mut t = DnsTracker::new();
        send_query(&mut t, 0, 1, "api.github.com");
        send_response(
            &mut t,
            20 * MS,
            1,
            "api.github.com",
            &[[140, 82, 121, 5]],
            0,
        );
        send_query(&mut t, 50 * MS, 2, "uploads.github.com");
        send_response(
            &mut t,
            70 * MS,
            2,
            "uploads.github.com",
            &[[140, 82, 121, 5], [140, 82, 121, 6]],
            0,
        );
        let shared = ip("140.82.121.5");
        // Both names point at the same address: both are offered, newest first.
        assert_eq!(
            t.likely_domains(shared, 1_000_000),
            vec!["uploads.github.com", "api.github.com"]
        );
        assert_eq!(
            t.likely_domains(ip("140.82.121.6"), 1_000_000),
            vec!["uploads.github.com"]
        );
        // Before the answers existed nothing is known.
        assert!(t.likely_domains(shared, 10 * MS).is_empty());
        assert!(t.likely_domains(ip("1.2.3.4"), i64::MAX).is_empty());
        assert_eq!(t.ips_for_domain("API.github.com."), vec![shared]);
    }

    #[test]
    fn cname_targets_are_attributed_too() {
        let mut t = DnsTracker::new();
        let m = response(
            4,
            "www.example.com",
            Some("edge.cdn.net"),
            &[[9, 9, 9, 9]],
            60,
            0,
        );
        send_query(&mut t, 0, 4, "www.example.com");
        t.observe(
            MS,
            ip(RESOLVER),
            53,
            ip(CLIENT),
            55000,
            None,
            &parse(&m).unwrap(),
        );
        let d = t.likely_domains(ip("9.9.9.9"), 10 * MS);
        assert!(
            d.contains(&"www.example.com".to_string()) && d.contains(&"edge.cdn.net".to_string()),
            "{d:?}"
        );
    }

    #[test]
    fn statistics_average_and_p95() {
        let mut t = DnsTracker::new();
        for i in 1..=20u16 {
            send_query(&mut t, i64::from(i) * 100_000, i, &format!("h{i}.example"));
            send_response(
                &mut t,
                i64::from(i) * 100_000 + i64::from(i) * MS,
                i,
                &format!("h{i}.example"),
                &[[1, 1, 1, 1]],
                0,
            );
        }
        let s = t.stats();
        assert_eq!((s.queries, s.responses, s.unique_domains), (20, 20, 20));
        assert_eq!(s.avg_latency, Some(10_500)); // mean of 1..=20 ms
        assert_eq!(s.p95_latency, Some(19 * MS)); // nearest rank: ceil(0.95*20)=19th
        assert_eq!(s.resolvers.len(), 1);
        assert_eq!(
            (s.resolvers[0].queries, s.resolvers[0].avg_latency),
            (20, Some(10_500))
        );
    }

    #[test]
    fn only_changes_are_reported() {
        let mut t = DnsTracker::new();
        send_query(&mut t, 0, 1, "a.example");
        assert_eq!(t.take_changed().len(), 1);
        assert!(t.take_changed().is_empty());
        assert!(t.take_stats_if_changed().is_some());
        assert!(t.take_stats_if_changed().is_none());
        send_response(&mut t, 10, 1, "a.example", &[[1, 1, 1, 1]], 0);
        assert_eq!(t.take_changed().len(), 1);
    }

    #[test]
    fn transaction_history_is_bounded() {
        let mut t = DnsTracker::new();
        for i in 0..(MAX_TRANSACTIONS as u64 + 50) {
            t.observe(
                i as i64,
                ip(CLIENT),
                (i % 60_000) as u16 + 1,
                ip(RESOLVER),
                53,
                None,
                &parse(&query(i as u16, "x.example", 1)).unwrap(),
            );
        }
        assert_eq!(t.snapshot().len(), MAX_TRANSACTIONS);
    }
}
