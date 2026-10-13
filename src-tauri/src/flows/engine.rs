use std::collections::{HashMap, HashSet};

use serde::Serialize;

use super::flow::{Direction, Flow, SPARK_WINDOW, TcpState};
use super::input::FlowInput;
use super::key::{Endpoint, FlowKey};
use crate::analytics::tls::TlsInfo;

pub const DEFAULT_MAX_FLOWS: usize = 500_000;

/// Serializable snapshot of a flow for the UI.
#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct FlowView {
    pub id: u64,
    pub protocol: String,
    pub application_protocol: Option<String>,
    pub endpoint_a: Endpoint,
    pub endpoint_b: Endpoint,
    pub started_at: i64,
    pub last_seen_at: i64,
    pub duration: i64,
    pub packets_a_to_b: u64,
    pub packets_b_to_a: u64,
    pub bytes_a_to_b: u64,
    pub bytes_b_to_a: u64,
    pub total_packets: u64,
    pub total_bytes: u64,
    pub tcp_state: Option<TcpState>,
    pub retransmissions: u64,
    pub resets: u64,
    pub duplicate_acks: u64,
    pub zero_windows: u64,
    pub latency: Option<i64>,
    pub domains: Vec<String>,
    pub process: Option<String>,
    pub tls: Option<TlsInfo>,
    pub sparkline: Vec<u64>,
}

impl FlowView {
    pub fn of(f: &Flow) -> Self {
        Self {
            id: f.id,
            protocol: f.proto.name(),
            application_protocol: guess_app(f),
            endpoint_a: f.endpoint_a,
            endpoint_b: f.endpoint_b,
            started_at: f.started_at,
            last_seen_at: f.last_seen_at,
            duration: f.duration_micros(),
            packets_a_to_b: f.packets_a_to_b,
            packets_b_to_a: f.packets_b_to_a,
            bytes_a_to_b: f.bytes_a_to_b,
            bytes_b_to_a: f.bytes_b_to_a,
            total_packets: f.total_packets(),
            total_bytes: f.total_bytes(),
            tcp_state: f.tcp_state,
            retransmissions: f.retransmissions,
            resets: f.resets,
            duplicate_acks: f.duplicate_acks,
            zero_windows: f.zero_windows,
            latency: f.handshake_rtt_micros,
            domains: f.domains.clone(),
            process: f.process.clone(),
            tls: f.tls.clone(),
            sparkline: {
                let s = f.sparkline();
                debug_assert_eq!(s.len(), SPARK_WINDOW);
                s
            },
        }
    }
}

fn guess_app(f: &Flow) -> Option<String> {
    use super::key::Proto::{Tcp, Udp};
    if f.tls.is_some() {
        return Some("TLS".to_string());
    }
    let by_port = |p: u16| match (f.proto, p) {
        (Tcp | Udp, 53) => Some("DNS"),
        (Udp, 5353) => Some("MDNS"),
        (Udp, 67 | 68) => Some("DHCP"),
        (Udp, 123) => Some("NTP"),
        (Udp, 443) => Some("QUIC"),
        (Tcp, 80 | 8080) => Some("HTTP"),
        (Tcp, 443) => Some("TLS"),
        (Tcp, 22) => Some("SSH"),
        _ => None,
    };
    by_port(f.endpoint_b.port)
        .or_else(|| by_port(f.endpoint_a.port))
        .map(str::to_string)
}

/// Result of folding one packet into the engine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Observed {
    pub id: u64,
    /// The packet opened a new flow.
    pub is_new: bool,
    pub state_before: Option<TcpState>,
    pub retransmissions_before: u64,
    pub resets_before: u64,
    pub duplicate_acks_before: u64,
    pub zero_windows_before: u64,
    /// Which way this packet travelled relative to the side that spoke first.
    pub direction: Direction,
}

/// Tracks every conversation seen so far. `observe` is O(1) per packet.
#[derive(Debug)]
pub struct FlowEngine {
    index: HashMap<FlowKey, u64>,
    flows: HashMap<u64, Flow>,
    dirty: HashSet<u64>,
    next_id: u64,
    max_flows: usize,
    pub evicted: u64,
}

impl Default for FlowEngine {
    fn default() -> Self {
        Self::new(DEFAULT_MAX_FLOWS)
    }
}

impl FlowEngine {
    pub fn new(max_flows: usize) -> Self {
        Self {
            index: HashMap::new(),
            flows: HashMap::new(),
            dirty: HashSet::new(),
            next_id: 1,
            max_flows: max_flows.max(1),
            evicted: 0,
        }
    }

    /// Folds one packet in; returns the id of the flow it belongs to.
    pub fn observe(&mut self, input: &FlowInput) -> u64 {
        self.observe_detailed(input).id
    }

    /// Like `observe`, but also reports what the packet changed (used for timeline events).
    pub fn observe_detailed(&mut self, input: &FlowInput) -> Observed {
        let key = FlowKey::new(input.proto, input.src, input.dst);
        let mut is_new = false;
        let id = match self.index.get(&key) {
            Some(&id) => id,
            None => {
                is_new = true;
                if self.flows.len() >= self.max_flows {
                    self.evict_idle();
                }
                let id = self.next_id;
                self.next_id += 1;
                self.index.insert(key, id);
                self.flows.insert(id, Flow::new(id, key, input));
                id
            }
        };
        let mut observed = Observed {
            id,
            is_new,
            state_before: None,
            retransmissions_before: 0,
            resets_before: 0,
            duplicate_acks_before: 0,
            zero_windows_before: 0,
            direction: Direction::AtoB,
        };
        if let Some(flow) = self.flows.get_mut(&id) {
            observed.state_before = flow.tcp_state;
            observed.retransmissions_before = flow.retransmissions;
            observed.resets_before = flow.resets;
            observed.duplicate_acks_before = flow.duplicate_acks;
            observed.zero_windows_before = flow.zero_windows;
            observed.direction = flow.direction_of(&input.src);
            flow.update(input);
        }
        self.dirty.insert(id);
        observed
    }

    /// Drops the least recently seen 1% (at least one) of flows to stay within the limit.
    fn evict_idle(&mut self) {
        let n = (self.max_flows / 100).max(1);
        let mut by_age: Vec<(i64, u64)> = self
            .flows
            .values()
            .map(|f| (f.last_seen_at, f.id))
            .collect();
        let n = n.min(by_age.len());
        by_age.select_nth_unstable(n - 1);
        for &(_, id) in &by_age[..n] {
            if let Some(f) = self.flows.remove(&id) {
                self.index.remove(&f.key);
                self.dirty.remove(&id);
                self.evicted += 1;
            }
        }
    }

    pub fn len(&self) -> usize {
        self.flows.len()
    }

    pub fn is_empty(&self) -> bool {
        self.flows.is_empty()
    }

    pub fn get(&self, id: u64) -> Option<&Flow> {
        self.flows.get(&id)
    }

    pub fn get_mut(&mut self, id: u64) -> Option<&mut Flow> {
        self.flows.get_mut(&id)
    }

    /// Stores TLS metadata on a flow and marks it as changed.
    pub fn set_tls(&mut self, id: u64, info: TlsInfo) {
        if let Some(f) = self.flows.get_mut(&id) {
            f.tls = Some(info);
            self.dirty.insert(id);
        }
    }

    /// Attaches likely domains to a flow (without duplicates) and marks it as changed.
    pub fn add_domains(&mut self, id: u64, domains: &[String]) {
        if let Some(f) = self.flows.get_mut(&id) {
            let before = f.domains.len();
            for d in domains {
                if !f.domains.contains(d) {
                    f.domains.push(d.clone());
                }
            }
            if f.domains.len() != before {
                self.dirty.insert(id);
            }
        }
    }

    /// Flows changed since the previous call, ordered by id.
    pub fn take_changed(&mut self) -> Vec<FlowView> {
        let mut ids: Vec<u64> = self.dirty.drain().collect();
        ids.sort_unstable();
        ids.iter()
            .filter_map(|id| self.flows.get(id))
            .map(FlowView::of)
            .collect()
    }

    pub fn snapshot_flows(&self) -> impl Iterator<Item = &Flow> {
        self.flows.values()
    }

    pub fn snapshot(&self) -> Vec<FlowView> {
        let mut v: Vec<FlowView> = self.flows.values().map(FlowView::of).collect();
        v.sort_by_key(|f| f.id);
        v
    }

    pub fn clear(&mut self) {
        *self = Self::new(self.max_flows);
    }
}
