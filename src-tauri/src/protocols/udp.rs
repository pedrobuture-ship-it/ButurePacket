use super::error::{ParseError, be16, need};

pub const HEADER_LEN: usize = 8;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Udp {
    pub src_port: u16,
    pub dst_port: u16,
    pub length: usize,
    pub checksum: u16,
}

pub fn parse(data: &[u8]) -> Result<Udp, ParseError> {
    need("UDP", data, HEADER_LEN)?;
    let length = usize::from(be16(data, 4));
    if length < HEADER_LEN {
        return Err(ParseError::Malformed {
            layer: "UDP",
            reason: "length below 8 bytes",
        });
    }
    Ok(Udp {
        src_port: be16(data, 0),
        dst_port: be16(data, 2),
        length,
        checksum: be16(data, 6),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_datagram_header() {
        let u = parse(&[0xd8, 0x41, 0, 53, 0, 58, 0xab, 0xcd]).unwrap();
        assert_eq!(
            (u.src_port, u.dst_port, u.length, u.checksum),
            (55361, 53, 58, 0xabcd)
        );
    }

    #[test]
    fn rejects_short_or_inconsistent() {
        assert!(matches!(parse(&[0; 7]), Err(ParseError::Truncated { .. })));
        assert!(matches!(
            parse(&[0, 1, 0, 2, 0, 4, 0, 0]),
            Err(ParseError::Malformed { .. })
        ));
    }
}
