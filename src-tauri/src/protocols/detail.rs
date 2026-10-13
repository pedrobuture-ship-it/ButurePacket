use serde::Serialize;

use super::dissect::{Dissection, L3, L4, dissect};
use super::ethernet::format_mac;
use super::summary::{PacketSummary, summarize_dissection};
use crate::capture::RawPacket;

/// One decoded protocol field and the bytes it came from (so the UI can highlight them).
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Field {
    pub name: String,
    pub value: String,
    pub offset: Option<usize>,
    pub length: usize,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Section {
    pub id: &'static str,
    pub title: String,
    /// Byte range covered by the whole section, when it maps to the frame.
    pub offset: Option<usize>,
    pub length: usize,
    pub fields: Vec<Field>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PacketDetail {
    pub summary: PacketSummary,
    pub sections: Vec<Section>,
    /// Captured bytes of the frame (at most the snap length).
    pub bytes: Vec<u8>,
}

struct SectionBuilder {
    section: Section,
    base: usize,
}

impl SectionBuilder {
    fn new(id: &'static str, title: &str, base: usize, length: usize) -> Self {
        Self {
            section: Section {
                id,
                title: title.into(),
                offset: Some(base),
                length,
                fields: vec![],
            },
            base,
        }
    }

    fn virt(id: &'static str, title: &str) -> Self {
        Self {
            section: Section {
                id,
                title: title.into(),
                offset: None,
                length: 0,
                fields: vec![],
            },
            base: 0,
        }
    }

    /// Field that maps to `length` bytes starting `rel` bytes into the section.
    fn field(&mut self, name: &str, value: impl Into<String>, rel: usize, length: usize) {
        self.section.fields.push(Field {
            name: name.into(),
            value: value.into(),
            offset: Some(self.base + rel),
            length,
        });
    }

    /// Derived value with no direct bytes.
    fn note(&mut self, name: &str, value: impl Into<String>) {
        self.section.fields.push(Field {
            name: name.into(),
            value: value.into(),
            offset: None,
            length: 0,
        });
    }
}

pub fn build_detail(raw: &RawPacket) -> PacketDetail {
    let d = dissect(&raw.data);
    let summary = summarize_dissection(raw, &d);
    let mut sections = vec![summary_section(&summary), frame_section(raw)];
    if let Some(s) = ethernet_section(&d) {
        sections.push(s);
    }
    if let Some(s) = network_section(&d) {
        sections.push(s);
    }
    if let Some(s) = transport_section(&d) {
        sections.push(s);
    }
    sections.push(application_section(&summary));
    sections.push(payload_section(&d));
    PacketDetail {
        summary,
        sections,
        bytes: raw.data.clone(),
    }
}

fn summary_section(s: &PacketSummary) -> Section {
    let mut b = SectionBuilder::virt("summary", "Summary");
    b.note(
        "Protocol",
        s.application_protocol
            .clone()
            .or_else(|| s.transport_protocol.clone())
            .unwrap_or_else(|| s.network_protocol.clone()),
    );
    let endpoint = |ip: &Option<String>, port: Option<u16>, mac: &Option<String>| match (ip, port) {
        (Some(ip), Some(p)) => format!("{ip}:{p}"),
        (Some(ip), None) => ip.clone(),
        _ => mac.clone().unwrap_or_else(|| "—".into()),
    };
    b.note(
        "Source",
        endpoint(&s.source_ip, s.source_port, &s.source_mac),
    );
    b.note(
        "Destination",
        endpoint(&s.destination_ip, s.destination_port, &s.destination_mac),
    );
    b.note("Info", s.info.clone());
    for issue in &s.issues {
        b.note("Warning", issue.clone());
    }
    b.section
}

fn frame_section(raw: &RawPacket) -> Section {
    let mut b = SectionBuilder::new("frame", "Frame", 0, raw.data.len());
    b.note("Frame number", raw.id.to_string());
    b.note("Arrival time", format_micros(raw.ts_micros));
    b.note("Captured length", format!("{} bytes", raw.captured_len));
    b.note("Original length", format!("{} bytes", raw.original_len));
    b.section
}

/// `2024-12-14 14:22:01.210000 UTC`
fn format_micros(micros: i64) -> String {
    let secs = micros.div_euclid(1_000_000);
    let frac = micros.rem_euclid(1_000_000);
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    format!(
        "{y:04}-{m:02}-{d:02} {:02}:{:02}:{:02}.{frac:06} UTC",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

/// Howard Hinnant's days→civil algorithm.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = yoe + era * 400 + i64::from(m <= 2);
    (y, m, d)
}

fn ethertype_name(t: u16) -> &'static str {
    match t {
        0x0800 => "IPv4",
        0x0806 => "ARP",
        0x86DD => "IPv6",
        _ => "Unknown",
    }
}

fn ethernet_section(d: &Dissection) -> Option<Section> {
    let e = d.eth.as_ref()?;
    let mut b = SectionBuilder::new("ethernet", "Ethernet II", 0, e.header_len);
    b.field("Destination MAC", format_mac(&e.dst), 0, 6);
    b.field("Source MAC", format_mac(&e.src), 6, 6);
    if let Some(v) = e.vlan {
        b.field("VLAN ID", v.to_string(), 14, 2);
    }
    b.field(
        "Type",
        format!("{} (0x{:04x})", ethertype_name(e.ethertype), e.ethertype),
        e.header_len - 2,
        2,
    );
    Some(b.section)
}

fn proto_name(p: u8) -> String {
    match p {
        1 => "ICMP (1)".into(),
        6 => "TCP (6)".into(),
        17 => "UDP (17)".into(),
        58 => "ICMPv6 (58)".into(),
        n => format!("Unknown ({n})"),
    }
}

fn network_section(d: &Dissection) -> Option<Section> {
    let base = d.l3_offset;
    match d.l3.as_ref()? {
        L3::V4(ip) => {
            let mut b = SectionBuilder::new("network", "Internet Protocol v4", base, ip.header_len);
            b.field(
                "Version / header length",
                format!("4 / {} bytes", ip.header_len),
                0,
                1,
            );
            b.field("DSCP / ECN", format!("0x{:02x}", ip.dscp_ecn), 1, 1);
            b.field("Total length", ip.total_len.to_string(), 2, 2);
            b.field(
                "Identification",
                format!("0x{:04x}", ip.identification),
                4,
                2,
            );
            let mut flags = vec![];
            if ip.dont_fragment {
                flags.push("DF");
            }
            if ip.more_fragments {
                flags.push("MF");
            }
            b.field(
                "Flags / fragment offset",
                format!(
                    "{} / {}",
                    if flags.is_empty() {
                        "none".into()
                    } else {
                        flags.join(", ")
                    },
                    ip.fragment_offset
                ),
                6,
                2,
            );
            b.field("TTL", ip.ttl.to_string(), 8, 1);
            b.field("Protocol", proto_name(ip.protocol), 9, 1);
            b.field("Header checksum", format!("0x{:04x}", ip.checksum), 10, 2);
            b.field("Source IP", ip.src.to_string(), 12, 4);
            b.field("Destination IP", ip.dst.to_string(), 16, 4);
            Some(b.section)
        }
        L3::V6(ip) => {
            let mut b = SectionBuilder::new("network", "Internet Protocol v6", base, ip.header_len);
            b.field(
                "Traffic class / flow label",
                format!("0x{:02x} / 0x{:05x}", ip.traffic_class, ip.flow_label),
                0,
                4,
            );
            b.field("Payload length", ip.payload_len.to_string(), 4, 2);
            b.field("Next header", proto_name(ip.next_header), 6, 1);
            b.field("Hop limit", ip.hop_limit.to_string(), 7, 1);
            b.field("Source IP", ip.src.to_string(), 8, 16);
            b.field("Destination IP", ip.dst.to_string(), 24, 16);
            if let Some(f) = &ip.fragment {
                b.note(
                    "Fragment",
                    format!(
                        "offset {} bytes, more fragments: {}, id 0x{:08x}",
                        f.offset, f.more_fragments, f.identification
                    ),
                );
            }
            Some(b.section)
        }
        L3::Arp(a) => {
            let mut b = SectionBuilder::new(
                "network",
                "Address Resolution Protocol",
                base,
                super::arp::HEADER_LEN,
            );
            b.field(
                "Operation",
                format!(
                    "{} ({})",
                    if a.operation == 1 {
                        "request"
                    } else if a.operation == 2 {
                        "reply"
                    } else {
                        "other"
                    },
                    a.operation
                ),
                6,
                2,
            );
            b.field("Sender MAC", format_mac(&a.sender_mac), 8, 6);
            b.field("Sender IP", a.sender_ip.to_string(), 14, 4);
            b.field("Target MAC", format_mac(&a.target_mac), 18, 6);
            b.field("Target IP", a.target_ip.to_string(), 24, 4);
            Some(b.section)
        }
        L3::Other(t) => {
            let mut b = SectionBuilder::virt("network", "Network Layer");
            b.note("EtherType", format!("0x{t:04x} (not decoded)"));
            Some(b.section)
        }
    }
}

fn transport_section(d: &Dissection) -> Option<Section> {
    let base = d.l4_offset;
    let hdr = d.payload_offset.saturating_sub(base);
    match d.l4.as_ref()? {
        L4::Tcp(t) => {
            let mut b =
                SectionBuilder::new("transport", "Transmission Control Protocol", base, hdr);
            b.field("Source port", t.src_port.to_string(), 0, 2);
            b.field("Destination port", t.dst_port.to_string(), 2, 2);
            b.field("Sequence number", t.seq.to_string(), 4, 4);
            b.field("Acknowledgment number", t.ack.to_string(), 8, 4);
            b.field("Header length", format!("{} bytes", t.header_len), 12, 1);
            b.field(
                "Flags",
                format!("0x{:03x} ({})", t.flags, t.flag_names().join(", ")),
                12,
                2,
            );
            b.field("Window size", t.window.to_string(), 14, 2);
            b.field("Checksum", format!("0x{:04x}", t.checksum), 16, 2);
            b.field("Urgent pointer", t.urgent.to_string(), 18, 2);
            if let Some(mss) = t.mss {
                b.field("Option: MSS", mss.to_string(), 20, hdr.saturating_sub(20));
            }
            Some(b.section)
        }
        L4::Udp(u) => {
            let mut b = SectionBuilder::new("transport", "User Datagram Protocol", base, hdr);
            b.field("Source port", u.src_port.to_string(), 0, 2);
            b.field("Destination port", u.dst_port.to_string(), 2, 2);
            b.field("Length", format!("{} bytes", u.length), 4, 2);
            b.field("Checksum", format!("0x{:04x}", u.checksum), 6, 2);
            Some(b.section)
        }
        L4::Icmp(i) => {
            let mut b = SectionBuilder::new(
                "transport",
                if i.v6 {
                    "ICMPv6"
                } else {
                    "Internet Control Message Protocol"
                },
                base,
                hdr,
            );
            b.field("Type", format!("{} ({})", i.icmp_type, i.describe()), 0, 1);
            b.field("Code", i.code.to_string(), 1, 1);
            b.field("Checksum", format!("0x{:04x}", i.checksum), 2, 2);
            Some(b.section)
        }
        L4::Other(p) => {
            let mut b = SectionBuilder::virt("transport", "Transport Layer");
            b.note("Protocol", format!("IP protocol {p} (not decoded)"));
            Some(b.section)
        }
    }
}

fn application_section(s: &PacketSummary) -> Section {
    let mut b = SectionBuilder::virt("application", "Application Protocol");
    match &s.application_protocol {
        Some(app) => b.note("Likely protocol", format!("{app} (inferred from port)")),
        None => b.note("Protocol", "Unavailable"),
    }
    b.section
}

fn payload_section(d: &Dissection) -> Section {
    let mut b = SectionBuilder::new("payload", "Payload", d.payload_offset, d.payload_len);
    b.field(
        "Length",
        format!("{} bytes", d.payload_len),
        0,
        d.payload_len,
    );
    b.section
}

#[cfg(test)]
mod tests {
    use super::*;
    use etherparse::PacketBuilder;

    fn raw_tcp() -> RawPacket {
        let b = PacketBuilder::ethernet2([1, 2, 3, 4, 5, 6], [7, 8, 9, 10, 11, 12])
            .ipv4([192, 168, 1, 20], [140, 82, 121, 4], 64)
            .tcp(53214, 443, 1000, 64240)
            .syn();
        let mut data = Vec::new();
        b.write(&mut data, b"hi").unwrap();
        RawPacket {
            id: 3,
            ts_micros: 1_734_186_121_210_000,
            captured_len: data.len() as u32,
            original_len: data.len() as u32,
            data,
        }
    }

    fn field<'a>(s: &'a Section, name: &str) -> &'a Field {
        s.fields
            .iter()
            .find(|f| f.name == name)
            .unwrap_or_else(|| panic!("no field {name}"))
    }

    fn section<'a>(d: &'a PacketDetail, id: &str) -> &'a Section {
        d.sections.iter().find(|s| s.id == id).unwrap()
    }

    #[test]
    fn field_offsets_point_at_the_right_bytes() {
        let raw = raw_tcp();
        let d = build_detail(&raw);
        let ip = section(&d, "network");
        let src = field(ip, "Source IP");
        assert_eq!(
            &raw.data[src.offset.unwrap()..src.offset.unwrap() + src.length],
            &[192, 168, 1, 20]
        );
        let tcp = section(&d, "transport");
        let dport = field(tcp, "Destination port");
        assert_eq!(
            &raw.data[dport.offset.unwrap()..][..2],
            &443u16.to_be_bytes()
        );
        let seq = field(tcp, "Sequence number");
        assert_eq!(
            &raw.data[seq.offset.unwrap()..][..4],
            &1000u32.to_be_bytes()
        );
        let eth = section(&d, "ethernet");
        assert_eq!(
            &raw.data[field(eth, "Source MAC").offset.unwrap()..][..6],
            &[1, 2, 3, 4, 5, 6]
        );
    }

    #[test]
    fn payload_section_covers_only_payload() {
        let raw = raw_tcp();
        let d = build_detail(&raw);
        let p = section(&d, "payload");
        assert_eq!(&raw.data[p.offset.unwrap()..][..p.length], b"hi");
    }

    #[test]
    fn section_order_matches_inspector_layout() {
        let ids: Vec<_> = build_detail(&raw_tcp())
            .sections
            .iter()
            .map(|s| s.id)
            .collect();
        assert_eq!(
            ids,
            [
                "summary",
                "frame",
                "ethernet",
                "network",
                "transport",
                "application",
                "payload"
            ]
        );
    }

    #[test]
    fn timestamp_formatting() {
        assert_eq!(
            format_micros(1_734_186_121_210_000),
            "2024-12-14 14:22:01.210000 UTC"
        );
        assert_eq!(format_micros(0), "1970-01-01 00:00:00.000000 UTC");
    }

    #[test]
    fn garbage_frames_still_produce_detail() {
        for data in [vec![], vec![1, 2, 3], vec![0xff; 200]] {
            let raw = RawPacket {
                id: 1,
                ts_micros: -5,
                captured_len: data.len() as u32,
                original_len: 999,
                data,
            };
            let d = build_detail(&raw);
            assert!(d.sections.iter().any(|s| s.id == "frame"));
        }
    }
}
