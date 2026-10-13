//! Live capture: libpcap source → bounded buffer → timed batches → sink.

pub mod error;
pub mod file;
pub mod interfaces;
pub mod linktype;
pub mod offline;
pub mod packet;
pub mod permission;
pub mod session;
pub mod source;
pub mod stats;

pub use error::CaptureError;
pub use interfaces::{InterfaceInfo, list_interfaces};
pub use packet::RawPacket;
pub use session::{CaptureSession, CaptureSink, SessionConfig, SessionState};
pub use source::{LiveSource, PacketSource};
pub use stats::StatsSnapshot;
