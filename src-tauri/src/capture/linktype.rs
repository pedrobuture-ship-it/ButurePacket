//! Converts captured frames from other link layers into Ethernet frames so one dissector serves all.

use std::borrow::Cow;

pub const LINKTYPE_NULL: u32 = 0;
pub const LINKTYPE_ETHERNET: u32 = 1;
pub const LINKTYPE_RAW: u32 = 101;
pub const LINKTYPE_LINUX_SLL: u32 = 113;
pub const LINKTYPE_IPV4: u32 = 228;
pub const LINKTYPE_IPV6: u32 = 229;
pub const LINKTYPE_LINUX_SLL2: u32 = 276;

const ETHERTYPE_IPV4: u16 = 0x0800;
const ETHERTYPE_IPV6: u16 = 0x86DD;

pub fn is_supported(linktype: u32) -> bool {
    matches!(
        linktype,
        LINKTYPE_NULL
            | LINKTYPE_ETHERNET
            | LINKTYPE_RAW
            | LINKTYPE_LINUX_SLL
            | LINKTYPE_IPV4
            | LINKTYPE_IPV6
            | LINKTYPE_LINUX_SLL2
    )
}

fn synthetic_ethernet(src: [u8; 6], ethertype: u16, payload: &[u8]) -> Vec<u8> {
    let mut f = Vec::with_capacity(14 + payload.len());
    f.extend([0u8; 6]);
    f.extend(src);
    f.extend(ethertype.to_be_bytes());
    f.extend(payload);
    f
}

fn ip_ethertype(first_byte: u8) -> Option<u16> {
    match first_byte >> 4 {
        4 => Some(ETHERTYPE_IPV4),
        6 => Some(ETHERTYPE_IPV6),
        _ => None,
    }
}

/// `None` when the link type is unsupported or the frame is too short to convert.
/// `big_endian` is the byte order of the capture file (matters for the BSD loopback header).
pub fn to_ethernet(linktype: u32, data: &[u8], big_endian: bool) -> Option<Cow<'_, [u8]>> {
    match linktype {
        LINKTYPE_ETHERNET => Some(Cow::Borrowed(data)),
        LINKTYPE_RAW | LINKTYPE_IPV4 | LINKTYPE_IPV6 => {
            let ty = ip_ethertype(*data.first()?)?;
            Some(Cow::Owned(synthetic_ethernet([0; 6], ty, data)))
        }
        LINKTYPE_NULL => {
            let family = {
                let b: [u8; 4] = data.get(..4)?.try_into().ok()?;
                if big_endian {
                    u32::from_be_bytes(b)
                } else {
                    u32::from_le_bytes(b)
                }
            };
            let ty = match family {
                2 => ETHERTYPE_IPV4,
                10 | 24 | 28 | 30 => ETHERTYPE_IPV6,
                _ => return None,
            };
            Some(Cow::Owned(synthetic_ethernet([0; 6], ty, &data[4..])))
        }
        LINKTYPE_LINUX_SLL => {
            let hdr = data.get(..16)?;
            let halen = u16::from_be_bytes([hdr[4], hdr[5]]);
            let mut src = [0u8; 6];
            if halen == 6 {
                src.copy_from_slice(&hdr[6..12]);
            }
            let ty = u16::from_be_bytes([hdr[14], hdr[15]]);
            Some(Cow::Owned(synthetic_ethernet(src, ty, &data[16..])))
        }
        LINKTYPE_LINUX_SLL2 => {
            let hdr = data.get(..20)?;
            let ty = u16::from_be_bytes([hdr[0], hdr[1]]);
            let halen = hdr[11];
            let mut src = [0u8; 6];
            if halen == 6 {
                src.copy_from_slice(&hdr[12..18]);
            }
            Some(Cow::Owned(synthetic_ethernet(src, ty, &data[20..])))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const IPV4_HEADER: [u8; 20] = [
        0x45, 0, 0, 20, 0, 0, 0, 0, 64, 6, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2,
    ];

    #[test]
    fn ethernet_is_untouched() {
        let d = [1u8, 2, 3];
        assert!(matches!(
            to_ethernet(LINKTYPE_ETHERNET, &d, false),
            Some(Cow::Borrowed(_))
        ));
    }

    #[test]
    fn raw_ip_gets_an_ethernet_header() {
        let f = to_ethernet(LINKTYPE_RAW, &IPV4_HEADER, false).unwrap();
        assert_eq!(&f[12..14], &[0x08, 0x00]);
        assert_eq!(&f[14..], &IPV4_HEADER);
        let mut v6 = vec![0x60u8];
        v6.extend([0u8; 39]);
        assert_eq!(
            &to_ethernet(LINKTYPE_IPV6, &v6, false).unwrap()[12..14],
            &[0x86, 0xDD]
        );
        assert!(to_ethernet(LINKTYPE_RAW, &[0x10, 0, 0], false).is_none());
        assert!(to_ethernet(LINKTYPE_RAW, &[], false).is_none());
    }

    #[test]
    fn bsd_loopback_family_respects_file_endianness() {
        let mut le = 2u32.to_le_bytes().to_vec();
        le.extend(IPV4_HEADER);
        assert_eq!(
            &to_ethernet(LINKTYPE_NULL, &le, false).unwrap()[12..14],
            &[0x08, 0x00]
        );
        let mut be = 2u32.to_be_bytes().to_vec();
        be.extend(IPV4_HEADER);
        assert_eq!(
            &to_ethernet(LINKTYPE_NULL, &be, true).unwrap()[12..14],
            &[0x08, 0x00]
        );
        assert!(to_ethernet(LINKTYPE_NULL, &99u32.to_le_bytes(), false).is_none());
    }

    #[test]
    fn linux_cooked_headers_are_translated() {
        let mut sll = vec![0, 0, 0, 1, 0, 6, 1, 2, 3, 4, 5, 6, 0, 0, 0x08, 0x00];
        sll.extend(IPV4_HEADER);
        let f = to_ethernet(LINKTYPE_LINUX_SLL, &sll, false).unwrap();
        assert_eq!(&f[6..12], &[1, 2, 3, 4, 5, 6]);
        assert_eq!(&f[12..14], &[0x08, 0x00]);
        assert_eq!(&f[14..], &IPV4_HEADER);

        let mut sll2 = vec![
            0x86, 0xDD, 0, 0, 0, 0, 0, 2, 0, 1, 0, 6, 9, 8, 7, 6, 5, 4, 0, 0,
        ];
        sll2.extend([0x60u8; 5]);
        let f = to_ethernet(LINKTYPE_LINUX_SLL2, &sll2, false).unwrap();
        assert_eq!(
            (&f[6..12], &f[12..14], &f[14..]),
            (
                &[9u8, 8, 7, 6, 5, 4][..],
                &[0x86u8, 0xDD][..],
                &[0x60u8; 5][..]
            )
        );
    }

    #[test]
    fn short_or_unknown_frames_are_rejected() {
        assert!(to_ethernet(LINKTYPE_LINUX_SLL, &[0; 15], false).is_none());
        assert!(to_ethernet(LINKTYPE_LINUX_SLL2, &[0; 19], false).is_none());
        assert!(to_ethernet(147, &[0; 100], false).is_none());
        assert!(!is_supported(147) && is_supported(113));
    }
}
