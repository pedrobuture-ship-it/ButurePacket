//! Deterministic synthetic traffic for benchmarks and manual testing: DNS lookups, TLS-over-TCP
//! conversations (handshake, request/response data, closes) and UDP bursts.

use etherparse::PacketBuilder;

use crate::capture::RawPacket;
use crate::protocols::dns::tests_support::{dns_query, dns_response};
use crate::protocols::tls::tests_support::{client_hello, server_hello};

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        // xorshift64*
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn below(&mut self, n: u64) -> u64 {
        self.next() % n.max(1)
    }
}

struct Conn {
    client: [u8; 4],
    server: [u8; 4],
    cport: u16,
    seq_c: u32,
    seq_s: u32,
    stage: u32,
    domain: String,
}

pub struct Synth {
    rng: Rng,
    conns: Vec<Conn>,
    next_id: u64,
    clock_micros: i64,
    max_conns: usize,
}

const CLIENT_BASE: [u8; 4] = [192, 168, 1, 20];
const RESOLVER: [u8; 4] = [8, 8, 8, 8];

impl Synth {
    /// `concurrent` is the number of simultaneously active TCP conversations.
    pub fn new(seed: u64, concurrent: usize) -> Self {
        Self {
            rng: Rng(seed | 1),
            conns: Vec::new(),
            next_id: 1,
            clock_micros: 1_700_000_000_000_000,
            max_conns: concurrent.max(1),
        }
    }

    fn new_conn(&mut self) -> Conn {
        let server = [
            140,
            82,
            (self.rng.below(250)) as u8,
            (self.rng.below(250) + 1) as u8,
        ];
        Conn {
            client: CLIENT_BASE,
            server,
            cport: 20_000 + self.rng.below(40_000) as u16,
            seq_c: self.rng.next() as u32,
            seq_s: self.rng.next() as u32,
            stage: 0,
            domain: format!("host{}.example.org", self.rng.below(500)),
        }
    }

    fn raw(&mut self, data: Vec<u8>) -> RawPacket {
        self.clock_micros += 20 + self.rng.below(200) as i64;
        let id = self.next_id;
        self.next_id += 1;
        RawPacket {
            id,
            ts_micros: self.clock_micros,
            captured_len: data.len() as u32,
            original_len: data.len() as u32,
            data,
        }
    }

    #[allow(clippy::too_many_arguments)] // flat packet fields; clearer than a one-use struct
    fn tcp(
        src: [u8; 4],
        dst: [u8; 4],
        sp: u16,
        dp: u16,
        seq: u32,
        ack: u32,
        syn: bool,
        fin: bool,
        payload: &[u8],
    ) -> Vec<u8> {
        let mut b = PacketBuilder::ethernet2([2, 0, 0, 0, 0, 1], [2, 0, 0, 0, 0, 2])
            .ipv4(src, dst, 64)
            .tcp(sp, dp, seq, 64_240);
        if syn {
            b = b.syn();
        }
        if fin {
            b = b.fin();
        }
        if ack != 0 {
            b = b.ack(ack);
        }
        let mut out = Vec::with_capacity(54 + payload.len());
        b.write(&mut out, payload).expect("synthetic frame");
        out
    }

    fn udp(src: [u8; 4], dst: [u8; 4], sp: u16, dp: u16, payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(42 + payload.len());
        PacketBuilder::ethernet2([2, 0, 0, 0, 0, 1], [2, 0, 0, 0, 0, 2])
            .ipv4(src, dst, 64)
            .udp(sp, dp)
            .write(&mut out, payload)
            .expect("synthetic frame");
        out
    }

    /// The next packet of the synthetic capture (id and timestamp increase monotonically).
    pub fn next_packet(&mut self) -> RawPacket {
        let roll = self.rng.below(100);
        if roll < 4 {
            // DNS query/response pair, emitted as two packets over successive calls via stage trick
            let name = format!("host{}.example.org", self.rng.below(500));
            let id = self.rng.below(65_536) as u16;
            let sport = 30_000 + self.rng.below(30_000) as u16;
            let data = if self.rng.below(2) == 0 {
                Self::udp(CLIENT_BASE, RESOLVER, sport, 53, &dns_query(id, &name))
            } else {
                Self::udp(
                    RESOLVER,
                    CLIENT_BASE,
                    53,
                    sport,
                    &dns_response(id, &name, &[[140, 82, self.rng.below(250) as u8, 7]]),
                )
            };
            return self.raw(data);
        }
        if roll < 18 {
            let sport = 40_000 + self.rng.below(10_000) as u16;
            let payload = vec![0xA5u8; 600 + self.rng.below(700) as usize];
            let data = Self::udp(CLIENT_BASE, [142, 250, 80, 46], sport, 443, &payload);
            return self.raw(data);
        }
        if self.conns.len() < self.max_conns {
            let c = self.new_conn();
            self.conns.push(c);
        }
        let idx = self.rng.below(self.conns.len() as u64) as usize;
        let from_client = self.rng.below(3) == 0;
        let data = {
            let c = &mut self.conns[idx];
            let (cl, sv, cp) = (c.client, c.server, c.cport);
            match c.stage {
                0 => {
                    c.stage = 1;
                    Self::tcp(cl, sv, cp, 443, c.seq_c, 0, true, false, &[])
                }
                1 => {
                    c.seq_c = c.seq_c.wrapping_add(1);
                    c.stage = 2;
                    Self::tcp(sv, cl, 443, cp, c.seq_s, c.seq_c, true, false, &[])
                }
                2 => {
                    c.seq_s = c.seq_s.wrapping_add(1);
                    c.stage = 3;
                    Self::tcp(cl, sv, cp, 443, c.seq_c, c.seq_s, false, false, &[])
                }
                3 => {
                    let hello = client_hello(&c.domain, &["h2", "http/1.1"]);
                    let d = Self::tcp(cl, sv, cp, 443, c.seq_c, c.seq_s, false, false, &hello);
                    c.seq_c = c.seq_c.wrapping_add(hello.len() as u32);
                    c.stage = 4;
                    d
                }
                4 => {
                    let hello = server_hello(true, 0x1301, None);
                    let d = Self::tcp(sv, cl, 443, cp, c.seq_s, c.seq_c, false, false, &hello);
                    c.seq_s = c.seq_s.wrapping_add(hello.len() as u32);
                    c.stage = 5;
                    d
                }
                s if s > 400 => {
                    let d = Self::tcp(cl, sv, cp, 443, c.seq_c, c.seq_s, false, true, &[]);
                    *c = Conn {
                        stage: 0,
                        cport: c.cport.wrapping_add(7).max(20_000),
                        ..Conn {
                            client: cl,
                            server: sv,
                            cport: cp,
                            seq_c: c.seq_c,
                            seq_s: c.seq_s,
                            stage: 0,
                            domain: c.domain.clone(),
                        }
                    };
                    d
                }
                _ => {
                    c.stage += 1;
                    if from_client {
                        let n = 100 + (c.stage as usize * 7) % 300;
                        let d = Self::tcp(
                            cl,
                            sv,
                            cp,
                            443,
                            c.seq_c,
                            c.seq_s,
                            false,
                            false,
                            &vec![0x17u8; n],
                        );
                        c.seq_c = c.seq_c.wrapping_add(n as u32);
                        d
                    } else {
                        let d = Self::tcp(
                            sv,
                            cl,
                            443,
                            cp,
                            c.seq_s,
                            c.seq_c,
                            false,
                            false,
                            &[0x42u8; 1400],
                        );
                        c.seq_s = c.seq_s.wrapping_add(1400);
                        d
                    }
                }
            }
        };
        self.raw(data)
    }

    pub fn batch(&mut self, n: usize) -> Vec<RawPacket> {
        (0..n).map(|_| self.next_packet()).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocols::{dissect, summarize};

    #[test]
    fn generator_is_deterministic_and_well_formed() {
        let a = Synth::new(7, 50).batch(2_000);
        let b = Synth::new(7, 50).batch(2_000);
        assert_eq!(a, b);
        assert!(
            a.windows(2)
                .all(|w| w[0].ts_micros < w[1].ts_micros && w[0].id + 1 == w[1].id)
        );
        // every frame decodes cleanly down to the transport layer
        assert!(a.iter().all(|p| dissect(&p.data).issues.is_empty()));
        let protos: std::collections::HashSet<_> = a
            .iter()
            .filter_map(|p| summarize(p).application_protocol)
            .collect();
        for want in ["DNS", "TLS", "QUIC"] {
            assert!(protos.contains(want), "{want} missing from {protos:?}");
        }
    }
}
