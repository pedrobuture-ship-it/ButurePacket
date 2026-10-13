//! Writes a synthetic capture for performance testing.
//!
//! ```text
//! cargo run --release --features testgen --example gen_pcap -- 1000000 /tmp/synthetic.pcap
//! ```

use std::fs::File;
use std::io::BufWriter;

use buturepacket_lib::capture::file::PcapWriter;
use buturepacket_lib::testgen::Synth;

fn main() {
    let mut args = std::env::args().skip(1);
    let count: u64 = args.next().and_then(|a| a.parse().ok()).unwrap_or(100_000);
    let path = args.next().unwrap_or_else(|| "synthetic.pcap".into());
    let mut synth = Synth::new(42, 800);
    let file = BufWriter::new(File::create(&path).expect("create output file"));
    let mut writer = PcapWriter::new(file).expect("write header");
    for _ in 0..count {
        writer.write(&synth.next_packet()).expect("write packet");
    }
    let n = writer.finish().expect("flush");
    println!("wrote {n} packets to {path}");
}
