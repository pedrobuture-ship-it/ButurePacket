use std::net::IpAddr;

use super::key::{Endpoint, Proto};
use crate::capture::RawPacket;
use crate::protocols::ipv4::{PROTO_TCP, PROTO_UDP};
use crate::protocols::{Dissection, L3, L4};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TcpInfo {
    pub seq: u32,
    pub ack: u32,
    pub flags: u16,
    pub window: u16,
    pub payload_len: u32,
}

/// The slice of a packet the flow engine cares about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FlowInput {
    pub ts_micros: i64,
    pub src: Endpoint,
    pub dst: Endpoint,
    pub proto: Proto,
    /// Bytes on the wire (original length).
    pub wire_len: u32,
    pub tcp: Option<TcpInfo>,
}

impl FlowInput {
    /// `None` for non-IP traffic (ARP, unknown EtherTypes) or when the IP header failed to decode.
    pub fn from_dissection(raw: &RawPacket, d: &Dissection) -> Option<Self> {
        let (src_ip, dst_ip, proto_num): (IpAddr, IpAddr, u8) = match d.l3.as_ref()? {
            L3::V4(ip) => (ip.src.into(), ip.dst.into(), ip.protocol),
            L3::V6(ip) => (ip.src.into(), ip.dst.into(), ip.next_header),
            _ => return None,
        };
        let (mut sp, mut dp, mut tcp) = (0, 0, None);
        let proto = match d.l4.as_ref() {
            Some(L4::Tcp(t)) => {
                (sp, dp) = (t.src_port, t.dst_port);
                tcp = Some(TcpInfo {
                    seq: t.seq,
                    ack: t.ack,
                    flags: t.flags,
                    window: t.window,
                    payload_len: u32::try_from(d.payload_len).unwrap_or(u32::MAX),
                });
                Proto::Tcp
            }
            Some(L4::Udp(u)) => {
                (sp, dp) = (u.src_port, u.dst_port);
                Proto::Udp
            }
            Some(L4::Icmp(i)) => {
                if i.v6 {
                    Proto::Icmpv6
                } else {
                    Proto::Icmp
                }
            }
            Some(L4::Other(p)) => Proto::from_number(*p),
            // A TCP/UDP header that could not be read (small snap length, non-first fragment) has
            // no ports: attributing it to a flow would merge every such packet between two hosts.
            None if matches!(proto_num, PROTO_TCP | PROTO_UDP) => return None,
            None => Proto::from_number(proto_num),
        };
        Some(Self {
            ts_micros: raw.ts_micros,
            src: Endpoint {
                ip: src_ip,
                port: sp,
            },
            dst: Endpoint {
                ip: dst_ip,
                port: dp,
            },
            proto,
            wire_len: raw.original_len.max(raw.captured_len),
            tcp,
        })
    }
}
