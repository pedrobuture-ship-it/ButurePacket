use std::collections::VecDeque;

use serde::{Deserialize, Serialize};

use super::input::{FlowInput, TcpInfo};
use super::key::{Endpoint, FlowKey, Proto};
use crate::analytics::tls::TlsInfo;
use crate::protocols::tcp::{ACK, FIN, RST, SYN};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TcpState {
    SynSent,
    SynReceived,
    Established,
    Closing,
    Closed,
    Reset,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    AtoB,
    BtoA,
}

/// Wrap-around-safe "a is before b" for 32-bit sequence numbers.
fn seq_lt(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) < 0
}

#[derive(Debug, Clone, Default)]
struct DirState {
    /// Highest sequence number (exclusive end) seen from this side.
    next_seq: Option<u32>,
    last_ack: Option<u32>,
    last_window: u16,
    dup_ack_run: u32,
    fin: bool,
}

/// Just over the 60 s sparkline window; more would cost memory per flow for nothing.
const SPARK_BUCKETS_KEPT: usize = 64;
pub const SPARK_WINDOW: usize = 60;

#[derive(Debug, Clone)]
pub struct Flow {
    pub id: u64,
    pub key: FlowKey,
    pub proto: Proto,
    /// The side that sent the first packet (the client, when the start of the connection was captured).
    pub endpoint_a: Endpoint,
    pub endpoint_b: Endpoint,
    pub started_at: i64,
    pub last_seen_at: i64,
    pub packets_a_to_b: u64,
    pub packets_b_to_a: u64,
    pub bytes_a_to_b: u64,
    pub bytes_b_to_a: u64,
    pub tcp_state: Option<TcpState>,
    pub retransmissions: u64,
    pub resets: u64,
    pub duplicate_acks: u64,
    pub zero_windows: u64,
    /// Round trip of the TCP handshake (SYN → SYN/ACK) in microseconds.
    pub handshake_rtt_micros: Option<i64>,
    pub domains: Vec<String>,
    pub process: Option<String>,
    /// TLS session metadata, when a handshake was observed.
    pub tls: Option<TlsInfo>,
    syn_at: Option<i64>,
    dir_a: DirState,
    dir_b: DirState,
    /// (unix second, bytes) pairs, oldest first.
    buckets: VecDeque<(i64, u64)>,
}

impl Flow {
    pub fn new(id: u64, key: FlowKey, input: &FlowInput) -> Self {
        // A SYN/ACK as first packet means we joined mid-handshake: the sender is the server.
        let first_is_server = input
            .tcp
            .is_some_and(|t| t.flags & (SYN | ACK) == (SYN | ACK));
        let (a, b) = if first_is_server {
            (input.dst, input.src)
        } else {
            (input.src, input.dst)
        };
        Self {
            id,
            key,
            proto: input.proto,
            endpoint_a: a,
            endpoint_b: b,
            started_at: input.ts_micros,
            last_seen_at: input.ts_micros,
            packets_a_to_b: 0,
            packets_b_to_a: 0,
            bytes_a_to_b: 0,
            bytes_b_to_a: 0,
            tcp_state: None,
            retransmissions: 0,
            resets: 0,
            duplicate_acks: 0,
            zero_windows: 0,
            handshake_rtt_micros: None,
            domains: vec![],
            process: None,
            tls: None,
            syn_at: None,
            dir_a: DirState::default(),
            dir_b: DirState::default(),
            buckets: VecDeque::new(),
        }
    }

    pub fn total_packets(&self) -> u64 {
        self.packets_a_to_b + self.packets_b_to_a
    }

    pub fn total_bytes(&self) -> u64 {
        self.bytes_a_to_b + self.bytes_b_to_a
    }

    pub fn duration_micros(&self) -> i64 {
        self.last_seen_at - self.started_at
    }

    pub fn direction_of(&self, src: &Endpoint) -> Direction {
        if *src == self.endpoint_a {
            Direction::AtoB
        } else {
            Direction::BtoA
        }
    }

    /// Incrementally folds one packet into the flow. Never rescans earlier packets.
    pub fn update(&mut self, input: &FlowInput) {
        let dir = self.direction_of(&input.src);
        match dir {
            Direction::AtoB => {
                self.packets_a_to_b += 1;
                self.bytes_a_to_b += u64::from(input.wire_len);
            }
            Direction::BtoA => {
                self.packets_b_to_a += 1;
                self.bytes_b_to_a += u64::from(input.wire_len);
            }
        }
        // Capture timestamps can be slightly out of order; keep the span monotone.
        self.last_seen_at = self.last_seen_at.max(input.ts_micros);
        self.started_at = self.started_at.min(input.ts_micros);
        self.record_bytes(input.ts_micros, u64::from(input.wire_len));
        if let Some(t) = input.tcp {
            self.update_tcp(dir, input.ts_micros, t);
        }
    }

    fn record_bytes(&mut self, ts_micros: i64, bytes: u64) {
        let sec = ts_micros.div_euclid(1_000_000);
        match self.buckets.back_mut() {
            Some((s, b)) if *s == sec => *b += bytes,
            Some((s, _)) if *s > sec => {
                // Late packet: attribute it to its own bucket if still retained.
                if let Some((_, b)) = self.buckets.iter_mut().rev().find(|(s, _)| *s == sec) {
                    *b += bytes;
                }
            }
            _ => {
                self.buckets.push_back((sec, bytes));
                if self.buckets.len() > SPARK_BUCKETS_KEPT {
                    self.buckets.pop_front();
                }
            }
        }
    }

    /// Bytes per second for the last `SPARK_WINDOW` seconds, ending at the last packet.
    pub fn sparkline(&self) -> Vec<u64> {
        let end = self.last_seen_at.div_euclid(1_000_000);
        let start = end - SPARK_WINDOW as i64 + 1;
        let mut out = vec![0u64; SPARK_WINDOW];
        for (s, b) in &self.buckets {
            if *s >= start && *s <= end {
                out[(*s - start) as usize] += b;
            }
        }
        out
    }

    fn update_tcp(&mut self, dir: Direction, ts: i64, t: TcpInfo) {
        let (syn, ack, fin, rst) = (
            t.flags & SYN != 0,
            t.flags & ACK != 0,
            t.flags & FIN != 0,
            t.flags & RST != 0,
        );

        if rst {
            self.resets += 1;
            self.tcp_state = Some(TcpState::Reset);
            return;
        }
        if t.window == 0 && !syn {
            self.zero_windows += 1;
        }

        // --- loss indicators (per direction) ---
        let seg_len = t
            .payload_len
            .wrapping_add(u32::from(syn))
            .wrapping_add(u32::from(fin));
        let me = match dir {
            Direction::AtoB => &mut self.dir_a,
            Direction::BtoA => &mut self.dir_b,
        };
        if seg_len > 0 {
            let end = t.seq.wrapping_add(seg_len);
            match me.next_seq {
                None => me.next_seq = Some(end),
                Some(next) => {
                    let keepalive =
                        t.payload_len == 1 && !syn && !fin && t.seq.wrapping_add(1) == next;
                    if seq_lt(t.seq, next) && !keepalive {
                        self.retransmissions += 1;
                    } else if seq_lt(next, end) {
                        me.next_seq = Some(end);
                    }
                }
            }
            me.dup_ack_run = 0;
        } else if ack && !fin {
            if me.last_ack == Some(t.ack) && me.last_window == t.window {
                me.dup_ack_run += 1;
                self.duplicate_acks += 1;
            } else {
                me.dup_ack_run = 0;
            }
        }
        if ack {
            me.last_ack = Some(t.ack);
        }
        me.last_window = t.window;
        if fin {
            me.fin = true;
        }

        // --- connection state ---
        if syn && !ack {
            if self.syn_at.is_none() {
                self.syn_at = Some(ts);
            }
            self.tcp_state.get_or_insert(TcpState::SynSent);
        } else if syn && ack {
            if let (Some(sent), None) = (self.syn_at, self.handshake_rtt_micros) {
                self.handshake_rtt_micros = Some((ts - sent).max(0));
            }
            if matches!(self.tcp_state, None | Some(TcpState::SynSent)) {
                self.tcp_state = Some(TcpState::SynReceived);
            }
        } else if self.dir_a.fin && self.dir_b.fin {
            self.tcp_state = Some(TcpState::Closed);
        } else if fin || self.dir_a.fin || self.dir_b.fin {
            self.tcp_state = Some(TcpState::Closing);
        } else if ack && !matches!(self.tcp_state, Some(TcpState::Closed | TcpState::Closing)) {
            // Handshake ACK or traffic on a flow that started before the capture.
            self.tcp_state = Some(TcpState::Established);
        }
    }
}
