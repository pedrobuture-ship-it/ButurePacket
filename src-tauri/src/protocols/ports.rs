//! Application protocols guessed from well-known ports. One table for the packet list and the
//! flow list so the two screens always agree. A guess, not a verdict: payload inspection (DNS,
//! TLS) overrides it where it can.

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Transport {
    Tcp,
    Udp,
}

pub fn well_known(transport: Transport, port: u16) -> Option<&'static str> {
    use Transport::{Tcp, Udp};
    match (transport, port) {
        (Tcp | Udp, 53) => Some("DNS"),
        (Udp, 5353) => Some("MDNS"),
        (Udp, 67 | 68) => Some("DHCP"),
        (Udp, 123) => Some("NTP"),
        (Udp, 443) => Some("QUIC"),
        (Tcp, 80 | 8080) => Some("HTTP"),
        (Tcp, 443) => Some("TLS"),
        (Tcp, 22) => Some("SSH"),
        _ => None,
    }
}

/// The protocol of a conversation: the server port wins, then the client port.
pub fn guess(transport: Transport, server_port: u16, client_port: u16) -> Option<&'static str> {
    well_known(transport, server_port).or_else(|| well_known(transport, client_port))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table() {
        assert_eq!(well_known(Transport::Udp, 53), Some("DNS"));
        assert_eq!(well_known(Transport::Tcp, 53), Some("DNS"));
        assert_eq!(well_known(Transport::Udp, 443), Some("QUIC"));
        assert_eq!(well_known(Transport::Tcp, 443), Some("TLS"));
        assert_eq!(well_known(Transport::Tcp, 8080), Some("HTTP"));
        assert_eq!(well_known(Transport::Udp, 80), None);
        assert_eq!(well_known(Transport::Tcp, 123), None);
    }

    #[test]
    fn server_port_takes_precedence() {
        assert_eq!(guess(Transport::Tcp, 443, 22), Some("TLS"));
        assert_eq!(guess(Transport::Tcp, 50000, 22), Some("SSH"));
        assert_eq!(guess(Transport::Udp, 50000, 50001), None);
    }
}
