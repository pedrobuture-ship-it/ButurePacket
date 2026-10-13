use std::net::Ipv6Addr;

use super::error::{ParseError, be16, be32, need};

const FIXED_LEN: usize = 40;
const MAX_EXTENSION_HEADERS: usize = 8;

const EXT_HOP_BY_HOP: u8 = 0;
const EXT_ROUTING: u8 = 43;
const EXT_FRAGMENT: u8 = 44;
const EXT_DEST_OPTIONS: u8 = 60;
pub const PROTO_ICMPV6: u8 = 58;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ipv6Fragment {
    /// Offset in bytes.
    pub offset: usize,
    pub more_fragments: bool,
    pub identification: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ipv6 {
    pub traffic_class: u8,
    pub flow_label: u32,
    /// Value of the payload-length field (0 may mean jumbo payload).
    pub payload_len: usize,
    /// Protocol of the upper layer, after skipping extension headers.
    pub next_header: u8,
    pub hop_limit: u8,
    pub src: Ipv6Addr,
    pub dst: Ipv6Addr,
    /// Fixed header plus any extension headers that were skipped.
    pub header_len: usize,
    pub fragment: Option<Ipv6Fragment>,
}

pub fn parse(data: &[u8]) -> Result<Ipv6, ParseError> {
    need("IPv6", data, FIXED_LEN)?;
    if data[0] >> 4 != 6 {
        return Err(ParseError::Malformed {
            layer: "IPv6",
            reason: "version is not 6",
        });
    }
    let mut src = [0u8; 16];
    let mut dst = [0u8; 16];
    src.copy_from_slice(&data[8..24]);
    dst.copy_from_slice(&data[24..40]);

    let mut next = data[6];
    let mut offset = FIXED_LEN;
    let mut fragment = None;
    for _ in 0..MAX_EXTENSION_HEADERS {
        match next {
            EXT_HOP_BY_HOP | EXT_ROUTING | EXT_DEST_OPTIONS => {
                need("IPv6 extension header", data, offset + 8)?;
                let len = (usize::from(data[offset + 1]) + 1) * 8;
                need("IPv6 extension header", data, offset + len)?;
                next = data[offset];
                offset += len;
            }
            EXT_FRAGMENT => {
                need("IPv6 fragment header", data, offset + 8)?;
                let field = be16(data, offset + 2);
                fragment = Some(Ipv6Fragment {
                    offset: usize::from(field >> 3) * 8,
                    more_fragments: field & 1 != 0,
                    identification: be32(data, offset + 4),
                });
                next = data[offset];
                offset += 8;
            }
            _ => break,
        }
    }
    Ok(Ipv6 {
        traffic_class: ((data[0] & 0x0F) << 4) | (data[1] >> 4),
        flow_label: (u32::from(data[1] & 0x0F) << 16) | u32::from(be16(data, 2)),
        payload_len: usize::from(be16(data, 4)),
        next_header: next,
        hop_limit: data[7],
        src: Ipv6Addr::from(src),
        dst: Ipv6Addr::from(dst),
        header_len: offset,
        fragment,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base(next: u8, payload: u16) -> Vec<u8> {
        let mut d = vec![0x60, 0, 0, 0, (payload >> 8) as u8, payload as u8, next, 64];
        d.extend([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        d.extend([0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
        d
    }

    #[test]
    fn parses_fixed_header() {
        let h = parse(&base(17, 8)).unwrap();
        assert_eq!(
            (h.next_header, h.hop_limit, h.payload_len, h.header_len),
            (17, 64, 8, 40)
        );
        assert_eq!(h.src.to_string(), "fe80::1");
        assert_eq!(h.dst.to_string(), "ff02::2");
        assert!(h.fragment.is_none());
    }

    #[test]
    fn skips_extension_headers() {
        let mut d = base(0, 16); // hop-by-hop
        d.extend([6, 0, 0, 0, 0, 0, 0, 0]); // next=TCP, len 8
        let h = parse(&d).unwrap();
        assert_eq!((h.next_header, h.header_len), (6, 48));
    }

    #[test]
    fn reports_fragment_header() {
        let mut d = base(44, 16);
        d.extend([17, 0, 0x00, 0x09, 0, 0, 0, 7]); // offset 1*8, MF
        let h = parse(&d).unwrap();
        let f = h.fragment.unwrap();
        assert_eq!((f.offset, f.more_fragments, f.identification), (8, true, 7));
        assert_eq!(h.next_header, 17);
    }

    #[test]
    fn rejects_hostile_input() {
        assert!(matches!(
            parse(&base(17, 0)[..39]),
            Err(ParseError::Truncated { .. })
        ));
        let mut bad = base(17, 0);
        bad[0] = 0x40;
        assert!(matches!(parse(&bad), Err(ParseError::Malformed { .. })));
        // extension header claims more bytes than exist
        let mut d = base(0, 0);
        d.extend([6, 200, 0, 0, 0, 0, 0, 0]);
        assert!(matches!(parse(&d), Err(ParseError::Truncated { .. })));
        // chain of hop-by-hop headers is bounded
        let mut chain = base(0, 0);
        for _ in 0..20 {
            chain.extend([0, 0, 0, 0, 0, 0, 0, 0]);
        }
        assert!(parse(&chain).is_ok());
    }
}
