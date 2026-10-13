use super::error::{ParseError, be16, need};

pub const ETHERTYPE_IPV4: u16 = 0x0800;
pub const ETHERTYPE_ARP: u16 = 0x0806;
pub const ETHERTYPE_IPV6: u16 = 0x86DD;
const ETHERTYPE_VLAN: u16 = 0x8100;
const ETHERTYPE_QINQ: u16 = 0x88A8;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ethernet {
    pub dst: [u8; 6],
    pub src: [u8; 6],
    /// EtherType of the encapsulated protocol (after any VLAN tags).
    pub ethertype: u16,
    /// Outermost VLAN id, if tagged.
    pub vlan: Option<u16>,
    pub header_len: usize,
}

pub fn format_mac(mac: &[u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}

pub fn parse(data: &[u8]) -> Result<Ethernet, ParseError> {
    need("Ethernet", data, 14)?;
    let mut dst = [0u8; 6];
    let mut src = [0u8; 6];
    dst.copy_from_slice(&data[0..6]);
    src.copy_from_slice(&data[6..12]);
    let mut ethertype = be16(data, 12);
    let mut header_len = 14;
    let mut vlan = None;
    // Up to two stacked tags (802.1Q / 802.1ad); more than that is treated as unknown payload.
    for _ in 0..2 {
        if ethertype != ETHERTYPE_VLAN && ethertype != ETHERTYPE_QINQ {
            break;
        }
        need("VLAN tag", data, header_len + 4)?;
        if vlan.is_none() {
            vlan = Some(be16(data, header_len) & 0x0FFF);
        }
        ethertype = be16(data, header_len + 2);
        header_len += 4;
    }
    Ok(Ethernet {
        dst,
        src,
        ethertype,
        vlan,
        header_len,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_plain_frame() {
        let mut f = vec![
            0x52, 0x54, 0, 0x12, 0x34, 0x56, 0x3c, 0xfd, 0xfe, 0x12, 0x34, 0x56, 0x08, 0x00,
        ];
        f.extend([0u8; 20]);
        let e = parse(&f).unwrap();
        assert_eq!(format_mac(&e.dst), "52:54:00:12:34:56");
        assert_eq!(format_mac(&e.src), "3c:fd:fe:12:34:56");
        assert_eq!(e.ethertype, ETHERTYPE_IPV4);
        assert_eq!((e.header_len, e.vlan), (14, None));
    }

    #[test]
    fn parses_vlan_tag() {
        let mut f = vec![0u8; 12];
        f.extend([0x81, 0x00, 0x00, 0x64, 0x86, 0xDD]);
        let e = parse(&f).unwrap();
        assert_eq!(
            (e.ethertype, e.vlan, e.header_len),
            (ETHERTYPE_IPV6, Some(100), 18)
        );
    }

    #[test]
    fn truncated_frames_error() {
        assert!(matches!(
            parse(&[0u8; 13]),
            Err(ParseError::Truncated {
                layer: "Ethernet",
                ..
            })
        ));
        let mut f = vec![0u8; 12];
        f.extend([0x81, 0x00, 0x00]);
        assert!(matches!(
            parse(&f),
            Err(ParseError::Truncated {
                layer: "VLAN tag",
                ..
            })
        ));
    }
}
