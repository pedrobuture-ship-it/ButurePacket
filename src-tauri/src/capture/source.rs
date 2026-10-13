use super::error::CaptureError;
use super::packet::RawPacket;

/// Anything that yields packets: a live libpcap handle, an offline file, or a test double.
pub trait PacketSource: Send {
    /// Returns `Ok(None)` when the read timed out with no packet (allows the
    /// caller to check for stop requests), `Err(EndOfStream)` when finished.
    fn next_packet(&mut self) -> Result<Option<RawPacket>, CaptureError>;

    /// Cumulative packets dropped by the kernel/driver, when known.
    fn kernel_dropped(&mut self) -> u64 {
        0
    }
}

pub struct LiveSource {
    cap: pcap::Capture<pcap::Active>,
}

pub const SNAPLEN: i32 = 65_535;
pub const READ_TIMEOUT_MS: i32 = 100;
const KERNEL_BUFFER_BYTES: i32 = 16 * 1024 * 1024;

impl LiveSource {
    pub fn open(interface: &str) -> Result<Self, CaptureError> {
        let cap = pcap::Capture::from_device(interface)?
            .promisc(true)
            .snaplen(SNAPLEN)
            .timeout(READ_TIMEOUT_MS)
            .immediate_mode(true)
            .buffer_size(KERNEL_BUFFER_BYTES)
            .open()?;
        if cap.get_datalink() != pcap::Linktype::ETHERNET {
            return Err(CaptureError::Backend(format!(
                "Unsupported link type {:?}: only Ethernet interfaces can be analysed.",
                cap.get_datalink()
            )));
        }
        Ok(Self { cap })
    }
}

impl PacketSource for LiveSource {
    #[allow(clippy::useless_conversion)] // timeval field widths differ per platform
    fn next_packet(&mut self) -> Result<Option<RawPacket>, CaptureError> {
        match self.cap.next_packet() {
            Ok(p) => Ok(Some(RawPacket {
                id: 0,
                ts_micros: i64::from(p.header.ts.tv_sec) * 1_000_000
                    + i64::from(p.header.ts.tv_usec),
                captured_len: p.header.caplen,
                original_len: p.header.len,
                data: p.data.to_vec(),
            })),
            Err(pcap::Error::TimeoutExpired) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    fn kernel_dropped(&mut self) -> u64 {
        self.cap
            .stats()
            .map(|s| u64::from(s.dropped) + u64::from(s.if_dropped))
            .unwrap_or(0)
    }
}
