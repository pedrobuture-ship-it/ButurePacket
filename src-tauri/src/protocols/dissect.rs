use super::dns::{self, Dns};
use super::error::ParseError;
use super::ethernet::{self, ETHERTYPE_ARP, ETHERTYPE_IPV4, ETHERTYPE_IPV6, Ethernet};
use super::ipv4::{self, Ipv4, PROTO_ICMP, PROTO_TCP, PROTO_UDP};
use super::ipv6::{self, Ipv6, PROTO_ICMPV6};
use super::tls::{self, TlsParse};
use super::{arp, icmp, tcp, udp};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum L3 {
    V4(Ipv4),
    V6(Ipv6),
    Arp(arp::Arp),
    /// Unrecognised EtherType.
    Other(u16),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum L4 {
    Tcp(tcp::Tcp),
    Udp(udp::Udp),
    Icmp(icmp::Icmp),
    /// Unrecognised IP protocol number.
    Other(u8),
}

/// Everything decoded from one frame. Offsets are relative to the start of the frame
/// so the UI can map protocol fields to bytes.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Dissection {
    pub eth: Option<Ethernet>,
    pub l3: Option<L3>,
    pub l3_offset: usize,
    pub l4: Option<L4>,
    pub l4_offset: usize,
    pub payload_offset: usize,
    pub payload_len: usize,
    pub fragmented: bool,
    /// Decoded DNS message when this is DNS over UDP/TCP port 53.
    pub dns: Option<Dns>,
    /// TLS records found in this segment's own payload (no cross-segment reassembly).
    pub tls: Option<TlsParse>,
    pub issues: Vec<ParseError>,
}

pub fn dissect(frame: &[u8]) -> Dissection {
    let mut d = Dissection::default();
    let eth = match ethernet::parse(frame) {
        Ok(e) => e,
        Err(e) => {
            d.issues.push(e);
            return d;
        }
    };
    d.l3_offset = eth.header_len;
    let ethertype = eth.ethertype;
    d.eth = Some(eth);
    let rest = &frame[d.l3_offset..];

    match ethertype {
        ETHERTYPE_IPV4 => dissect_ipv4(&mut d, rest),
        ETHERTYPE_IPV6 => dissect_ipv6(&mut d, rest),
        ETHERTYPE_ARP => match arp::parse(rest) {
            Ok(a) => d.l3 = Some(L3::Arp(a)),
            Err(e) => d.issues.push(e),
        },
        other => d.l3 = Some(L3::Other(other)),
    }
    d
}

fn dissect_ipv4(d: &mut Dissection, l3: &[u8]) {
    let ip = match ipv4::parse(l3) {
        Ok(ip) => ip,
        Err(e) => {
            d.issues.push(e);
            return;
        }
    };
    // The IP total length excludes Ethernet padding; a larger value means the capture was cut short.
    let end = if ip.total_len > l3.len() {
        d.issues.push(ParseError::Truncated {
            layer: "IPv4 payload",
            needed: ip.total_len,
            available: l3.len(),
        });
        l3.len()
    } else {
        ip.total_len
    };
    let (header_len, protocol, offset) = (ip.header_len, ip.protocol, ip.fragment_offset);
    d.fragmented = ip.is_fragment();
    d.l3 = Some(L3::V4(ip));
    dissect_transport(d, l3, header_len, end, protocol, offset > 0, false);
}

fn dissect_ipv6(d: &mut Dissection, l3: &[u8]) {
    let ip = match ipv6::parse(l3) {
        Ok(ip) => ip,
        Err(e) => {
            d.issues.push(e);
            return;
        }
    };
    let declared = if ip.payload_len == 0 {
        l3.len()
    } else {
        40 + ip.payload_len
    };
    let end = if declared > l3.len() {
        d.issues.push(ParseError::Truncated {
            layer: "IPv6 payload",
            needed: declared,
            available: l3.len(),
        });
        l3.len()
    } else {
        declared
    };
    let (header_len, protocol) = (ip.header_len, ip.next_header);
    let later_fragment = ip.fragment.as_ref().is_some_and(|f| f.offset > 0);
    d.fragmented = ip.fragment.is_some();
    d.l3 = Some(L3::V6(ip));
    dissect_transport(d, l3, header_len, end, protocol, later_fragment, true);
}

fn dissect_transport(
    d: &mut Dissection,
    l3: &[u8],
    header_len: usize,
    end: usize,
    protocol: u8,
    later_fragment: bool,
    v6: bool,
) {
    let start = header_len.min(end);
    let data = &l3[start..end];
    d.l4_offset = d.l3_offset + start;
    d.payload_offset = d.l4_offset;
    d.payload_len = data.len();
    if later_fragment {
        return; // non-first fragments carry no transport header
    }
    let result: Result<(L4, usize), ParseError> = match protocol {
        PROTO_TCP => tcp::parse(data).map(|t| {
            let n = t.header_len;
            (L4::Tcp(t), n)
        }),
        PROTO_UDP => udp::parse(data).map(|u| (L4::Udp(u), udp::HEADER_LEN)),
        PROTO_ICMP if !v6 => icmp::parse(data, false).map(|i| (L4::Icmp(i), icmp::HEADER_LEN)),
        PROTO_ICMPV6 if v6 => icmp::parse(data, true).map(|i| (L4::Icmp(i), icmp::HEADER_LEN)),
        other => {
            d.l4 = Some(L4::Other(other));
            return;
        }
    };
    match result {
        Ok((l4, hdr)) => {
            let hdr = hdr.min(data.len());
            d.payload_offset = d.l4_offset + hdr;
            d.payload_len = data.len() - hdr;
            d.dns = decode_dns(&l4, &data[hdr..]);
            if matches!(l4, L4::Tcp(_)) && tls::looks_like_tls(&data[hdr..]) {
                d.tls = Some(tls::parse(&data[hdr..]));
            }
            d.l4 = Some(l4);
        }
        Err(e) => d.issues.push(e),
    }
}

/// DNS over UDP, or over TCP when the whole message fits in this segment (2-byte length prefix).
fn decode_dns(l4: &L4, payload: &[u8]) -> Option<Dns> {
    match l4 {
        L4::Udp(u) if u.src_port == 53 || u.dst_port == 53 => dns::parse(payload).ok(),
        L4::Tcp(t) if t.src_port == 53 || t.dst_port == 53 => {
            let len = usize::from(u16::from_be_bytes([*payload.first()?, *payload.get(1)?]));
            (len > 0 && payload.len() == len + 2)
                .then(|| dns::parse(&payload[2..]).ok())
                .flatten()
        }
        _ => None,
    }
}
