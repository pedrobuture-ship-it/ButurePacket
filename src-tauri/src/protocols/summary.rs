use serde::Serialize;

use super::dissect::{Dissection, L3, L4, dissect};
use super::ethernet::format_mac;
use crate::capture::RawPacket;

/// Compact per-packet record sent to the UI. Never contains the payload.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PacketSummary {
    pub id: u64,
    /// Conversation this packet belongs to, once the flow engine has seen it.
    pub flow_id: Option<u64>,
    /// Microseconds since the Unix epoch.
    pub timestamp: i64,
    pub captured_length: u32,
    pub original_length: u32,
    pub source_mac: Option<String>,
    pub destination_mac: Option<String>,
    pub source_ip: Option<String>,
    pub destination_ip: Option<String>,
    pub source_port: Option<u16>,
    pub destination_port: Option<u16>,
    pub network_protocol: String,
    pub transport_protocol: Option<String>,
    pub application_protocol: Option<String>,
    pub tcp_flags: Option<Vec<&'static str>>,
    pub ttl: Option<u8>,
    pub payload_length: u32,
    pub info: String,
    /// Non-fatal problems: truncation, malformed headers, fragmentation.
    pub issues: Vec<String>,
}

/// Best-effort application protocol from well-known ports. Refined by payload inspection elsewhere.
fn guess_application(transport: &str, src: u16, dst: u16) -> Option<&'static str> {
    let by_port = |p: u16| match (transport, p) {
        ("UDP" | "TCP", 53) => Some("DNS"),
        ("UDP", 5353) => Some("MDNS"),
        ("UDP", 67 | 68) => Some("DHCP"),
        ("UDP", 123) => Some("NTP"),
        ("UDP", 443) => Some("QUIC"),
        ("TCP", 80 | 8080) => Some("HTTP"),
        ("TCP", 443) => Some("TLS"),
        ("TCP", 22) => Some("SSH"),
        _ => None,
    };
    by_port(dst).or_else(|| by_port(src))
}

pub fn summarize(packet: &RawPacket) -> PacketSummary {
    summarize_dissection(packet, &dissect(&packet.data))
}

pub fn summarize_dissection(packet: &RawPacket, d: &Dissection) -> PacketSummary {
    let (mut sip, mut dip, mut ttl) = (None, None, None);
    let network = match &d.l3 {
        Some(L3::V4(ip)) => {
            (sip, dip, ttl) = (
                Some(ip.src.to_string()),
                Some(ip.dst.to_string()),
                Some(ip.ttl),
            );
            "IPv4".to_string()
        }
        Some(L3::V6(ip)) => {
            (sip, dip, ttl) = (
                Some(ip.src.to_string()),
                Some(ip.dst.to_string()),
                Some(ip.hop_limit),
            );
            "IPv6".to_string()
        }
        Some(L3::Arp(a)) => {
            (sip, dip) = (Some(a.sender_ip.to_string()), Some(a.target_ip.to_string()));
            "ARP".to_string()
        }
        Some(L3::Other(t)) => format!("Unknown (0x{t:04x})"),
        None => "Unknown".to_string(),
    };

    let (mut sport, mut dport, mut flags) = (None, None, None);
    let transport = match &d.l4 {
        Some(L4::Tcp(t)) => {
            (sport, dport, flags) = (Some(t.src_port), Some(t.dst_port), Some(t.flag_names()));
            Some("TCP".to_string())
        }
        Some(L4::Udp(u)) => {
            (sport, dport) = (Some(u.src_port), Some(u.dst_port));
            Some("UDP".to_string())
        }
        Some(L4::Icmp(i)) => Some(if i.v6 { "ICMPv6" } else { "ICMP" }.to_string()),
        Some(L4::Other(p)) => Some(format!("IP proto {p}")),
        None => None,
    };
    let application = match (&transport, sport, dport) {
        (Some(t), Some(s), Some(dst)) => guess_application(t, s, dst).map(str::to_string),
        _ => None,
    };

    let mut issues: Vec<String> = d.issues.iter().map(ToString::to_string).collect();
    if d.fragmented {
        issues.push("Fragmented IP packet".into());
    }

    PacketSummary {
        id: packet.id,
        flow_id: None,
        timestamp: packet.ts_micros,
        captured_length: packet.captured_len,
        original_length: packet.original_len,
        source_mac: d.eth.as_ref().map(|e| format_mac(&e.src)),
        destination_mac: d.eth.as_ref().map(|e| format_mac(&e.dst)),
        source_ip: sip,
        destination_ip: dip,
        source_port: sport,
        destination_port: dport,
        network_protocol: network,
        transport_protocol: transport,
        application_protocol: application,
        tcp_flags: flags,
        ttl,
        payload_length: u32::try_from(d.payload_len).unwrap_or(u32::MAX),
        info: info_text(d),
        issues,
    }
}

fn info_text(d: &Dissection) -> String {
    let tail = if d.fragmented { " [Fragment]" } else { "" };
    let base = match (&d.l3, &d.l4) {
        (Some(L3::Arp(a)), _) => a.describe(),
        (_, Some(L4::Tcp(t))) => {
            let mut s = format!(
                "{} → {} [{}] Seq={} Win={} Len={}",
                t.src_port,
                t.dst_port,
                t.flag_names().join(", "),
                t.seq,
                t.window,
                d.payload_len
            );
            if t.has(super::tcp::ACK) {
                s.push_str(&format!(" Ack={}", t.ack));
            }
            if let Some(mss) = t.mss {
                s.push_str(&format!(" MSS={mss}"));
            }
            s
        }
        (_, Some(L4::Udp(u))) => format!("{} → {} Len={}", u.src_port, u.dst_port, d.payload_len),
        (_, Some(L4::Icmp(i))) => i.describe(),
        (_, Some(L4::Other(p))) => format!("IP protocol {p}"),
        (Some(L3::Other(t)), _) => format!("EtherType 0x{t:04x}"),
        _ => d
            .issues
            .first()
            .map(ToString::to_string)
            .unwrap_or_else(|| "Unparsed frame".to_string()),
    };
    format!("{base}{tail}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use etherparse::PacketBuilder;

    fn raw(data: Vec<u8>) -> RawPacket {
        RawPacket {
            id: 7,
            ts_micros: 1_700_000_000_000_000,
            captured_len: data.len() as u32,
            original_len: data.len() as u32,
            data,
        }
    }

    fn build_tcp_syn() -> Vec<u8> {
        let b = PacketBuilder::ethernet2([1, 2, 3, 4, 5, 6], [7, 8, 9, 10, 11, 12])
            .ipv4([192, 168, 1, 20], [140, 82, 121, 4], 64)
            .tcp(53214, 443, 1000, 64240)
            .syn();
        let mut out = Vec::new();
        b.write(&mut out, &[]).unwrap();
        out
    }

    #[test]
    fn tcp_over_ipv4_summary() {
        let s = summarize(&raw(build_tcp_syn()));
        assert_eq!(s.network_protocol, "IPv4");
        assert_eq!(s.transport_protocol.as_deref(), Some("TCP"));
        assert_eq!(
            (s.source_ip.as_deref(), s.destination_ip.as_deref()),
            (Some("192.168.1.20"), Some("140.82.121.4"))
        );
        assert_eq!(
            (s.source_port, s.destination_port, s.ttl),
            (Some(53214), Some(443), Some(64))
        );
        assert_eq!(s.tcp_flags, Some(vec!["SYN"]));
        assert_eq!(s.application_protocol.as_deref(), Some("TLS"));
        assert_eq!(s.source_mac.as_deref(), Some("01:02:03:04:05:06"));
        assert!(s.issues.is_empty());
        assert_eq!(s.payload_length, 0);
        assert!(s.info.starts_with("53214 → 443 [SYN]"));
    }

    #[test]
    fn udp_over_ipv6_with_payload() {
        let b = PacketBuilder::ethernet2([1; 6], [2; 6])
            .ipv6(
                [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
                [0; 16],
                32,
            )
            .udp(5000, 53);
        let mut out = Vec::new();
        b.write(&mut out, b"hello").unwrap();
        let s = summarize(&raw(out));
        assert_eq!(s.network_protocol, "IPv6");
        assert_eq!(s.transport_protocol.as_deref(), Some("UDP"));
        assert_eq!(s.application_protocol.as_deref(), Some("DNS"));
        assert_eq!((s.payload_length, s.ttl), (5, Some(32)));
    }

    #[test]
    fn icmp_echo_request() {
        let b = PacketBuilder::ethernet2([1; 6], [2; 6])
            .ipv4([10, 0, 0, 1], [10, 0, 0, 2], 64)
            .icmpv4_echo_request(1, 1);
        let mut out = Vec::new();
        b.write(&mut out, &[]).unwrap();
        let s = summarize(&raw(out));
        assert_eq!(s.transport_protocol.as_deref(), Some("ICMP"));
        assert_eq!(s.info, "Echo (ping) request");
    }

    #[test]
    fn arp_request_summary() {
        let mut f = vec![0xff; 6];
        f.extend([1, 2, 3, 4, 5, 6, 0x08, 0x06]);
        f.extend([
            0, 1, 8, 0, 6, 4, 0, 1, 1, 2, 3, 4, 5, 6, 192, 168, 1, 20, 0, 0, 0, 0, 0, 0, 192, 168,
            1, 1,
        ]);
        let s = summarize(&raw(f));
        assert_eq!(s.network_protocol, "ARP");
        assert_eq!(s.info, "Who has 192.168.1.1? Tell 192.168.1.20");
    }

    #[test]
    fn unknown_ethertype_and_protocol() {
        let mut f = vec![0u8; 12];
        f.extend([0x88, 0xcc]);
        f.extend([0u8; 10]);
        let s = summarize(&raw(f));
        assert_eq!(s.network_protocol, "Unknown (0x88cc)");
        assert_eq!(s.info, "EtherType 0x88cc");
    }

    #[test]
    fn truncated_capture_is_flagged_but_still_summarised() {
        let full = build_tcp_syn();
        let cut = full[..full.len() - 8].to_vec(); // chop the end of the TCP header
        let s = summarize(&raw(cut));
        assert_eq!(s.network_protocol, "IPv4");
        assert!(
            s.issues.iter().any(|i| i.contains("Truncated")),
            "{:?}",
            s.issues
        );
        assert!(s.transport_protocol.is_none());
    }

    #[test]
    fn ethernet_padding_is_not_counted_as_payload() {
        let b = PacketBuilder::ethernet2([1; 6], [2; 6])
            .ipv4([1, 1, 1, 1], [2, 2, 2, 2], 9)
            .udp(1, 2);
        let mut out = Vec::new();
        b.write(&mut out, b"ab").unwrap();
        out.extend([0u8; 18]); // trailing padding
        let s = summarize(&raw(out));
        assert_eq!(s.payload_length, 2);
    }

    #[test]
    fn ipv4_fragments_are_marked() {
        let mut f = vec![0u8; 12];
        f.extend([0x08, 0x00]);
        f.extend([
            0x45, 0, 0, 28, 0, 1, 0x20, 0, 64, 17, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2,
        ]); // MF set
        f.extend([0x04, 0xd2, 0x00, 0x35, 0x00, 0x20, 0, 0]);
        let s = summarize(&raw(f));
        assert!(s.issues.iter().any(|i| i.contains("Fragment")));
        assert!(s.info.ends_with("[Fragment]"));
        // later fragment: no ports because the transport header isn't there
        let mut g = vec![0u8; 12];
        g.extend([0x08, 0x00]);
        g.extend([
            0x45, 0, 0, 28, 0, 1, 0x00, 0x10, 64, 17, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2,
        ]);
        g.extend([1, 2, 3, 4, 5, 6, 7, 8]);
        let s = summarize(&raw(g));
        assert_eq!(s.source_port, None);
        assert_eq!(s.payload_length, 8);
    }

    #[test]
    fn hostile_inputs_never_panic() {
        // Every prefix of a valid frame, plus every single-byte mutation of its headers.
        let base = build_tcp_syn();
        for n in 0..=base.len() {
            let _ = summarize(&raw(base[..n].to_vec()));
        }
        for i in 0..base.len() {
            for v in [0u8, 1, 0x0f, 0x7f, 0x80, 0xff] {
                let mut m = base.clone();
                m[i] = v;
                let _ = summarize(&raw(m));
            }
        }
        let _ = summarize(&raw(vec![]));
        let _ = summarize(&raw(vec![0xff; 70_000]));
    }
}
