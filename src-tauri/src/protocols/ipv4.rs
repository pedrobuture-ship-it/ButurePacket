use std::net::Ipv4Addr;

use super::error::{ParseError, be16, need};

pub const PROTO_ICMP: u8 = 1;
pub const PROTO_TCP: u8 = 6;
pub const PROTO_UDP: u8 = 17;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ipv4 {
    pub header_len: usize,
    pub dscp_ecn: u8,
    pub total_len: usize,
    pub identification: u16,
    pub dont_fragment: bool,
    pub more_fragments: bool,
    /// Fragment offset in bytes.
    pub fragment_offset: usize,
    pub ttl: u8,
    pub protocol: u8,
    pub checksum: u16,
    pub src: Ipv4Addr,
    pub dst: Ipv4Addr,
}

impl Ipv4 {
    pub fn is_fragment(&self) -> bool {
        self.more_fragments || self.fragment_offset > 0
    }
}

pub fn parse(data: &[u8]) -> Result<Ipv4, ParseError> {
    need("IPv4", data, 20)?;
    if data[0] >> 4 != 4 {
        return Err(ParseError::Malformed {
            layer: "IPv4",
            reason: "version is not 4",
        });
    }
    let header_len = usize::from(data[0] & 0x0F) * 4;
    if header_len < 20 {
        return Err(ParseError::Malformed {
            layer: "IPv4",
            reason: "header length below 20 bytes",
        });
    }
    need("IPv4", data, header_len)?;
    let total_len = usize::from(be16(data, 2));
    if total_len < header_len {
        return Err(ParseError::Malformed {
            layer: "IPv4",
            reason: "total length smaller than header",
        });
    }
    let frag = be16(data, 6);
    Ok(Ipv4 {
        header_len,
        dscp_ecn: data[1],
        total_len,
        identification: be16(data, 4),
        dont_fragment: frag & 0x4000 != 0,
        more_fragments: frag & 0x2000 != 0,
        fragment_offset: usize::from(frag & 0x1FFF) * 8,
        ttl: data[8],
        protocol: data[9],
        checksum: be16(data, 10),
        src: Ipv4Addr::new(data[12], data[13], data[14], data[15]),
        dst: Ipv4Addr::new(data[16], data[17], data[18], data[19]),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header() -> Vec<u8> {
        vec![
            0x45, 0, 0, 0x34, 0xab, 0xcd, 0x40, 0, 64, 6, 0x12, 0x34, 192, 168, 1, 20, 140, 82,
            121, 4,
        ]
    }

    #[test]
    fn parses_basic_header() {
        let h = parse(&header()).unwrap();
        assert_eq!(
            (h.header_len, h.total_len, h.ttl, h.protocol),
            (20, 52, 64, PROTO_TCP)
        );
        assert_eq!(h.src, Ipv4Addr::new(192, 168, 1, 20));
        assert_eq!(h.dst, Ipv4Addr::new(140, 82, 121, 4));
        assert!(h.dont_fragment && !h.is_fragment());
    }

    #[test]
    fn detects_fragments() {
        let mut d = header();
        d[6] = 0x20; // MF, offset 0
        assert!(parse(&d).unwrap().is_fragment());
        d[6] = 0x00;
        d[7] = 0x10; // offset 16*8
        let h = parse(&d).unwrap();
        assert_eq!(h.fragment_offset, 128);
        assert!(h.is_fragment());
    }

    #[test]
    fn rejects_bad_headers() {
        let mut d = header();
        d[0] = 0x65;
        assert!(matches!(parse(&d), Err(ParseError::Malformed { .. })));
        d[0] = 0x44;
        assert!(matches!(parse(&d), Err(ParseError::Malformed { .. })));
        d[0] = 0x4F; // IHL 60 > data
        assert!(matches!(parse(&d), Err(ParseError::Truncated { .. })));
        d[0] = 0x45;
        d[3] = 10; // total length < header
        assert!(matches!(parse(&d), Err(ParseError::Malformed { .. })));
        assert!(matches!(
            parse(&header()[..19]),
            Err(ParseError::Truncated { .. })
        ));
    }
}
