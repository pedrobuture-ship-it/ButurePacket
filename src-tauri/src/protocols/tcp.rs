use super::error::{ParseError, be16, be32, need};

pub const FIN: u16 = 0x001;
pub const SYN: u16 = 0x002;
pub const RST: u16 = 0x004;
pub const PSH: u16 = 0x008;
pub const ACK: u16 = 0x010;
pub const URG: u16 = 0x020;
pub const ECE: u16 = 0x040;
pub const CWR: u16 = 0x080;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tcp {
    pub src_port: u16,
    pub dst_port: u16,
    pub seq: u32,
    pub ack: u32,
    pub header_len: usize,
    pub flags: u16,
    pub window: u16,
    pub checksum: u16,
    pub urgent: u16,
    pub mss: Option<u16>,
}

pub fn parse(data: &[u8]) -> Result<Tcp, ParseError> {
    need("TCP", data, 20)?;
    let header_len = usize::from(data[12] >> 4) * 4;
    if header_len < 20 {
        return Err(ParseError::Malformed {
            layer: "TCP",
            reason: "data offset below 5 words",
        });
    }
    need("TCP", data, header_len)?;
    Ok(Tcp {
        src_port: be16(data, 0),
        dst_port: be16(data, 2),
        seq: be32(data, 4),
        ack: be32(data, 8),
        header_len,
        flags: (u16::from(data[12] & 1) << 8) | u16::from(data[13]),
        window: be16(data, 14),
        checksum: be16(data, 16),
        urgent: be16(data, 18),
        mss: find_mss(&data[20..header_len]),
    })
}

fn find_mss(mut opts: &[u8]) -> Option<u16> {
    while let Some(&kind) = opts.first() {
        match kind {
            0 => return None,
            1 => opts = &opts[1..],
            _ => {
                let len = usize::from(*opts.get(1)?);
                if len < 2 || len > opts.len() {
                    return None;
                }
                if kind == 2 && len == 4 {
                    return Some(be16(opts, 2));
                }
                opts = &opts[len..];
            }
        }
    }
    None
}

impl Tcp {
    pub fn has(&self, flag: u16) -> bool {
        self.flags & flag != 0
    }

    /// Flag names in Wireshark order, e.g. `["SYN", "ACK"]`.
    pub fn flag_names(&self) -> Vec<&'static str> {
        const NAMES: [(u16, &str); 8] = [
            (SYN, "SYN"),
            (FIN, "FIN"),
            (RST, "RST"),
            (PSH, "PSH"),
            (ACK, "ACK"),
            (URG, "URG"),
            (ECE, "ECE"),
            (CWR, "CWR"),
        ];
        NAMES
            .iter()
            .filter(|(bit, _)| self.has(*bit))
            .map(|(_, n)| *n)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn syn() -> Vec<u8> {
        let mut d = vec![
            0xd1, 0xb6, 0x01, 0xbb, 0, 0, 0, 1, 0, 0, 0, 0, 0x70, 0x02, 0xfa, 0xf0, 0, 0, 0, 0,
        ];
        d.extend([2, 4, 5, 0xb4, 1, 1, 4, 2]); // MSS 1460, NOP, NOP, SACK-permitted
        d
    }

    #[test]
    fn parses_syn_with_mss() {
        let t = parse(&syn()).unwrap();
        assert_eq!(
            (t.src_port, t.dst_port, t.seq, t.header_len),
            (53686, 443, 1, 28)
        );
        assert_eq!(t.flag_names(), vec!["SYN"]);
        assert_eq!((t.window, t.mss), (64240, Some(1460)));
    }

    #[test]
    fn flag_order_and_bits() {
        let mut d = syn();
        d[13] = 0x12;
        assert_eq!(parse(&d).unwrap().flag_names(), vec!["SYN", "ACK"]);
        d[13] = 0x19;
        assert_eq!(parse(&d).unwrap().flag_names(), vec!["FIN", "PSH", "ACK"]);
    }

    #[test]
    fn rejects_bad_offsets() {
        let mut d = syn();
        d[12] = 0x40;
        assert!(matches!(parse(&d), Err(ParseError::Malformed { .. })));
        d[12] = 0xF0;
        assert!(matches!(parse(&d), Err(ParseError::Truncated { .. })));
        assert!(matches!(
            parse(&syn()[..19]),
            Err(ParseError::Truncated { .. })
        ));
    }

    #[test]
    fn hostile_options_do_not_panic() {
        for bad in [&[2u8][..], &[2, 0], &[2, 200, 0], &[3, 3], &[1, 1, 1, 0]] {
            let mut d = syn();
            d.truncate(20);
            d.extend(bad);
            while !d.len().is_multiple_of(4) {
                d.push(0);
            }
            d[12] = ((d.len() / 4) as u8) << 4;
            assert!(parse(&d).is_ok());
        }
    }
}
