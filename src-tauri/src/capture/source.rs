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
    linktype: u32,
}

pub const SNAPLEN: i32 = 65_535;
pub const READ_TIMEOUT_MS: i32 = 100;
const KERNEL_BUFFER_BYTES: i32 = 16 * 1024 * 1024;

impl LiveSource {
    pub fn open(interface: &str) -> Result<Self, CaptureError> {
        let cap = pcap::Capture::from_device(interface)
            .and_then(|c| {
                c.promisc(true)
                    .snaplen(SNAPLEN)
                    .timeout(READ_TIMEOUT_MS)
                    .immediate_mode(true)
                    .buffer_size(KERNEL_BUFFER_BYTES)
                    .open()
            })
            .map_err(|e| match CaptureError::from(e) {
                // pcap's text names no interface; we know which one we tried.
                CaptureError::InterfaceNotFound(_) => {
                    CaptureError::InterfaceNotFound(interface.to_string())
                }
                other => other,
            })?;
        let linktype = u32::try_from(cap.get_datalink().0).unwrap_or(u32::MAX);
        if !super::linktype::is_supported(linktype) {
            return Err(CaptureError::Backend(format!(
                "This interface uses link type {linktype}, which cannot be analysed. Supported: Ethernet, Linux cooked, raw IP and loopback."
            )));
        }
        Ok(Self { cap, linktype })
    }
}

impl PacketSource for LiveSource {
    #[allow(clippy::useless_conversion)] // timeval field widths differ per platform
    fn next_packet(&mut self) -> Result<Option<RawPacket>, CaptureError> {
        match self.cap.next_packet() {
            Ok(p) => {
                let ts_micros =
                    i64::from(p.header.ts.tv_sec) * 1_000_000 + i64::from(p.header.ts.tv_usec);
                // Other link layers (e.g. the "any" device) are rewritten as Ethernet frames.
                let Some(frame) = super::linktype::to_ethernet(self.linktype, p.data, false) else {
                    return Ok(None); // too short to convert: skip quietly
                };
                let delta = frame.len() as i64 - p.data.len() as i64;
                let original = (i64::from(p.header.len) + delta).max(frame.len() as i64);
                Ok(Some(RawPacket {
                    id: 0,
                    ts_micros,
                    captured_len: frame.len() as u32,
                    original_len: u32::try_from(original).unwrap_or(u32::MAX),
                    data: frame.into_owned(),
                }))
            }
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
