/// A packet exactly as it came off the wire, before any parsing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawPacket {
    /// Sequential id assigned when the packet is accepted into the buffer (starts at 1).
    pub id: u64,
    /// Capture timestamp in microseconds since the Unix epoch.
    pub ts_micros: i64,
    pub captured_len: u32,
    pub original_len: u32,
    pub data: Vec<u8>,
}

impl RawPacket {
    /// Approximate memory footprint, used to enforce buffer limits.
    pub fn mem_size(&self) -> usize {
        self.data.len() + std::mem::size_of::<Self>()
    }
}
