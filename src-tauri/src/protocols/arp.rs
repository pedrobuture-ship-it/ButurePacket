use std::net::Ipv4Addr;

use super::error::{ParseError, be16, need};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Arp {
    pub operation: u16,
    pub sender_mac: [u8; 6],
    pub sender_ip: Ipv4Addr,
    pub target_mac: [u8; 6],
    pub target_ip: Ipv4Addr,
}

pub const HEADER_LEN: usize = 28;

pub fn parse(data: &[u8]) -> Result<Arp, ParseError> {
    need("ARP", data, HEADER_LEN)?;
    // Only Ethernet/IPv4 ARP is decoded.
    if be16(data, 0) != 1 || be16(data, 2) != 0x0800 || data[4] != 6 || data[5] != 4 {
        return Err(ParseError::Malformed {
            layer: "ARP",
            reason: "unsupported hardware/protocol type",
        });
    }
    let mut sender_mac = [0u8; 6];
    let mut target_mac = [0u8; 6];
    sender_mac.copy_from_slice(&data[8..14]);
    target_mac.copy_from_slice(&data[18..24]);
    Ok(Arp {
        operation: be16(data, 6),
        sender_mac,
        sender_ip: Ipv4Addr::new(data[14], data[15], data[16], data[17]),
        target_mac,
        target_ip: Ipv4Addr::new(data[24], data[25], data[26], data[27]),
    })
}

impl Arp {
    pub fn describe(&self) -> String {
        match self.operation {
            1 => format!("Who has {}? Tell {}", self.target_ip, self.sender_ip),
            2 => format!(
                "{} is at {}",
                self.sender_ip,
                super::ethernet::format_mac(&self.sender_mac)
            ),
            op => format!("ARP operation {op}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> Vec<u8> {
        let mut d = vec![0, 1, 8, 0, 6, 4, 0, 1];
        d.extend([1, 2, 3, 4, 5, 6, 192, 168, 1, 20]);
        d.extend([0; 6]);
        d.extend([192, 168, 1, 1]);
        d
    }

    #[test]
    fn parses_request() {
        let a = parse(&request()).unwrap();
        assert_eq!(a.operation, 1);
        assert_eq!(a.describe(), "Who has 192.168.1.1? Tell 192.168.1.20");
    }

    #[test]
    fn rejects_truncated_and_foreign_types() {
        assert!(matches!(
            parse(&request()[..27]),
            Err(ParseError::Truncated { .. })
        ));
        let mut r = request();
        r[5] = 16;
        assert!(matches!(parse(&r), Err(ParseError::Malformed { .. })));
    }
}
