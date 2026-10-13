//! Hand-written, bounds-checked protocol parsers. None of them may panic on hostile input.

pub mod arp;
pub mod detail;
pub mod dissect;
pub mod dns;
pub mod error;
pub mod ethernet;
pub mod icmp;
pub mod ipv4;
pub mod ipv6;
pub mod ports;
pub mod summary;
pub mod tcp;
pub mod tls;
pub mod udp;

pub use detail::{PacketDetail, build_detail};
pub use dissect::{Dissection, L3, L4, dissect};
pub use error::ParseError;
pub use summary::{PacketSummary, summarize};
