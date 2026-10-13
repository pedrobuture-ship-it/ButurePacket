use std::collections::VecDeque;

use crate::capture::RawPacket;

/// Bounded in-memory store of raw packets so payloads can be fetched on demand.
/// Oldest packets are evicted first once the byte limit is exceeded.
#[derive(Debug)]
pub struct PacketStore {
    packets: VecDeque<RawPacket>,
    bytes: usize,
    max_bytes: usize,
}

pub const DEFAULT_MAX_BYTES: usize = 512 * 1024 * 1024;

impl Default for PacketStore {
    fn default() -> Self {
        Self::new(DEFAULT_MAX_BYTES)
    }
}

impl PacketStore {
    pub fn new(max_bytes: usize) -> Self {
        Self {
            packets: VecDeque::new(),
            bytes: 0,
            max_bytes,
        }
    }

    pub fn push(&mut self, packet: RawPacket) {
        self.bytes += packet.mem_size();
        self.packets.push_back(packet);
        while self.bytes > self.max_bytes && self.packets.len() > 1 {
            if let Some(old) = self.packets.pop_front() {
                self.bytes -= old.mem_size();
            }
        }
    }

    /// Ids are assigned sequentially, so lookup is an index computation.
    pub fn get(&self, id: u64) -> Option<&RawPacket> {
        let first = self.packets.front()?.id;
        let idx = usize::try_from(id.checked_sub(first)?).ok()?;
        self.packets.get(idx).filter(|p| p.id == id)
    }

    pub fn len(&self) -> usize {
        self.packets.len()
    }

    pub fn is_empty(&self) -> bool {
        self.packets.is_empty()
    }

    pub fn clear(&mut self) {
        self.packets.clear();
        self.bytes = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pkt(id: u64, len: usize) -> RawPacket {
        RawPacket {
            id,
            ts_micros: 0,
            captured_len: len as u32,
            original_len: len as u32,
            data: vec![id as u8; len],
        }
    }

    #[test]
    fn lookup_by_id() {
        let mut s = PacketStore::default();
        (1..=10).for_each(|i| s.push(pkt(i, 10)));
        assert_eq!(s.get(5).unwrap().data[0], 5);
        assert!(s.get(0).is_none() && s.get(11).is_none());
    }

    #[test]
    fn evicts_oldest_when_over_limit() {
        let mut s = PacketStore::new(3 * pkt(1, 100).mem_size());
        (1..=10).for_each(|i| s.push(pkt(i, 100)));
        assert_eq!(s.len(), 3);
        assert!(s.get(7).is_none());
        assert_eq!(s.get(8).unwrap().id, 8);
        s.clear();
        assert!(s.is_empty() && s.get(10).is_none());
    }
}
