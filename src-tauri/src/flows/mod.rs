//! Flow engine: groups packets into bidirectional conversations, incrementally.

pub mod engine;
pub mod flow;
pub mod input;
pub mod key;

pub use engine::{FlowEngine, FlowView, Observed};
pub use flow::{Direction, Flow, TcpState};
pub use input::{FlowInput, TcpInfo};
pub use key::{Endpoint, FlowKey, Proto};

#[cfg(test)]
mod tests;
