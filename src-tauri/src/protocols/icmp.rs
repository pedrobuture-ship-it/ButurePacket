use super::error::{ParseError, be16, need};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Icmp {
    pub v6: bool,
    pub icmp_type: u8,
    pub code: u8,
    pub checksum: u16,
}

pub const HEADER_LEN: usize = 8;

pub fn parse(data: &[u8], v6: bool) -> Result<Icmp, ParseError> {
    let layer = if v6 { "ICMPv6" } else { "ICMP" };
    need(layer, data, 4)?;
    Ok(Icmp {
        v6,
        icmp_type: data[0],
        code: data[1],
        checksum: be16(data, 2),
    })
}

impl Icmp {
    pub fn describe(&self) -> String {
        let name = if self.v6 {
            match self.icmp_type {
                1 => "Destination unreachable",
                2 => "Packet too big",
                3 => "Time exceeded",
                128 => "Echo (ping) request",
                129 => "Echo (ping) reply",
                133 => "Router solicitation",
                134 => "Router advertisement",
                135 => "Neighbor solicitation",
                136 => "Neighbor advertisement",
                _ => return format!("ICMPv6 type {} code {}", self.icmp_type, self.code),
            }
        } else {
            match self.icmp_type {
                0 => "Echo (ping) reply",
                3 => "Destination unreachable",
                5 => "Redirect",
                8 => "Echo (ping) request",
                11 => "Time exceeded",
                _ => return format!("ICMP type {} code {}", self.icmp_type, self.code),
            }
        };
        name.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn describes_echo() {
        assert_eq!(
            parse(&[8, 0, 0xf7, 0xff, 0, 1, 0, 1], false)
                .unwrap()
                .describe(),
            "Echo (ping) request"
        );
        assert_eq!(
            parse(&[129, 0, 0, 0], true).unwrap().describe(),
            "Echo (ping) reply"
        );
        assert_eq!(
            parse(&[200, 7, 0, 0], false).unwrap().describe(),
            "ICMP type 200 code 7"
        );
    }

    #[test]
    fn truncated_errors() {
        assert!(matches!(
            parse(&[8, 0, 0], false),
            Err(ParseError::Truncated { layer: "ICMP", .. })
        ));
        assert!(matches!(
            parse(&[], true),
            Err(ParseError::Truncated {
                layer: "ICMPv6",
                ..
            })
        ));
    }
}
