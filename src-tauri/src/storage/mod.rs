//! Persistence: a bounded in-memory raw-packet store for payload lookups, plus a SQLite layer
//! (derived records only, never raw bytes) written in batches by a background thread.

pub mod database;
pub mod dns;
pub mod events;
pub mod flows;
pub mod memory;
pub mod packets;
pub mod writer;
