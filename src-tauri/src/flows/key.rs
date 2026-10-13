use std::net::IpAddr;

use serde::Serialize;

use crate::protocols::ipv4::{PROTO_ICMP, PROTO_TCP, PROTO_UDP};
use crate::protocols::ipv6::PROTO_ICMPV6;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Proto {
    Tcp,
    Udp,
    Icmp,
    Icmpv6,
    Other(u8),
}

impl Proto {
    pub fn from_number(n: u8) -> Self {
        match n {
            PROTO_TCP => Proto::Tcp,
            PROTO_UDP => Proto::Udp,
            PROTO_ICMP => Proto::Icmp,
            PROTO_ICMPV6 => Proto::Icmpv6,
            other => Proto::Other(other),
        }
    }

    pub fn name(self) -> String {
        match self {
            Proto::Tcp => "TCP".into(),
            Proto::Udp => "UDP".into(),
            Proto::Icmp => "ICMP".into(),
            Proto::Icmpv6 => "ICMPv6".into(),
            Proto::Other(n) => format!("IP proto {n}"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
pub struct Endpoint {
    pub ip: IpAddr,
    pub port: u16,
}

/// Direction-independent identity of a conversation: the two endpoints are stored in
/// sorted order so A→B and B→A packets map to the same key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FlowKey {
    pub proto: Proto,
    low: Endpoint,
    high: Endpoint,
}

impl FlowKey {
    pub fn new(proto: Proto, a: Endpoint, b: Endpoint) -> Self {
        if a <= b {
            Self {
                proto,
                low: a,
                high: b,
            }
        } else {
            Self {
                proto,
                low: b,
                high: a,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ep(ip: &str, port: u16) -> Endpoint {
        Endpoint {
            ip: ip.parse().unwrap(),
            port,
        }
    }

    #[test]
    fn key_is_direction_independent() {
        let a = ep("192.168.1.20", 53214);
        let b = ep("140.82.121.4", 443);
        assert_eq!(
            FlowKey::new(Proto::Tcp, a, b),
            FlowKey::new(Proto::Tcp, b, a)
        );
    }

    #[test]
    fn key_distinguishes_protocol_port_and_address() {
        let a = ep("10.0.0.1", 1000);
        let b = ep("10.0.0.2", 80);
        let base = FlowKey::new(Proto::Tcp, a, b);
        assert_ne!(base, FlowKey::new(Proto::Udp, a, b));
        assert_ne!(base, FlowKey::new(Proto::Tcp, ep("10.0.0.1", 1001), b));
        assert_ne!(base, FlowKey::new(Proto::Tcp, a, ep("10.0.0.3", 80)));
    }

    #[test]
    fn v4_and_v6_never_collide() {
        let v4 = FlowKey::new(Proto::Udp, ep("1.2.3.4", 1), ep("5.6.7.8", 2));
        let v6 = FlowKey::new(Proto::Udp, ep("::ffff:1.2.3.4", 1), ep("::ffff:5.6.7.8", 2));
        assert_ne!(v4, v6);
    }

    #[test]
    fn protocol_names() {
        assert_eq!(Proto::from_number(6).name(), "TCP");
        assert_eq!(Proto::from_number(47).name(), "IP proto 47");
    }
}
