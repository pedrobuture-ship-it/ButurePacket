//! Packet → parser → flow engine → (later: correlation, analytics). One place where a batch is processed.

use std::sync::Mutex;

use crate::capture::RawPacket;
use crate::flows::{FlowEngine, FlowInput, FlowView};
use crate::protocols::{PacketSummary, dissect, summary::summarize_dissection};
use crate::storage::memory::PacketStore;

/// What one processed batch produced for the UI.
#[derive(Debug, Default)]
pub struct Processed {
    pub packets: Vec<PacketSummary>,
    pub flows: Vec<FlowView>,
}

#[derive(Default)]
pub struct Pipeline {
    pub store: Mutex<PacketStore>,
    pub flows: Mutex<FlowEngine>,
}

impl Pipeline {
    pub fn process(&self, batch: Vec<RawPacket>) -> Processed {
        let mut packets = Vec::with_capacity(batch.len());
        let mut flows = self.flows.lock().unwrap();
        for raw in &batch {
            let d = dissect(&raw.data);
            packets.push(summarize_dissection(raw, &d));
            if let Some(input) = FlowInput::from_dissection(raw, &d) {
                flows.observe(&input);
            }
        }
        let changed = flows.take_changed();
        drop(flows);
        let mut store = self.store.lock().unwrap();
        for raw in batch {
            store.push(raw);
        }
        Processed {
            packets,
            flows: changed,
        }
    }

    pub fn clear(&self) {
        self.store.lock().unwrap().clear();
        self.flows.lock().unwrap().clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use etherparse::PacketBuilder;

    fn frame(id: u64, sport: u16) -> RawPacket {
        let b = PacketBuilder::ethernet2([1; 6], [2; 6])
            .ipv4([10, 0, 0, 1], [10, 0, 0, 2], 64)
            .udp(sport, 53);
        let mut data = vec![];
        b.write(&mut data, b"x").unwrap();
        RawPacket {
            id,
            ts_micros: id as i64 * 1000,
            captured_len: data.len() as u32,
            original_len: data.len() as u32,
            data,
        }
    }

    #[test]
    fn batch_produces_summaries_flows_and_stores_raw() {
        let p = Pipeline::default();
        let out = p.process(vec![frame(1, 5000), frame(2, 5000), frame(3, 6000)]);
        assert_eq!(out.packets.len(), 3);
        assert_eq!(out.flows.len(), 2);
        assert_eq!(p.store.lock().unwrap().get(2).unwrap().id, 2);
        // second batch only reports flows that changed
        let out = p.process(vec![frame(4, 6000)]);
        assert_eq!(out.flows.len(), 1);
        assert_eq!(out.flows[0].total_packets, 2);
    }

    #[test]
    fn clear_empties_everything() {
        let p = Pipeline::default();
        p.process(vec![frame(1, 5000)]);
        p.clear();
        assert!(p.store.lock().unwrap().is_empty());
        assert!(p.flows.lock().unwrap().is_empty());
    }
}
