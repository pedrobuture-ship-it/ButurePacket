//! PCAP and PCAPNG reading/writing. Files are untrusted: every length is validated, nothing is
//! allocated from an unchecked size, and a damaged file ends in a typed error, never a panic.

use std::io::{self, BufReader, Read, Seek, SeekFrom, Write};

use super::error::CaptureError;
use super::linktype::{self, to_ethernet};
use super::packet::RawPacket;

/// Largest single packet accepted (libpcap's own limit is 262144).
pub const MAX_PACKET_BYTES: u32 = 262_144;
/// Largest PCAPNG block read into memory.
const MAX_BLOCK_BYTES: u32 = 16 * 1024 * 1024;
const READ_BUFFER: usize = 1 << 20;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Pcap,
    PcapNg,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct FileStats {
    /// Packets returned to the caller.
    pub packets: u64,
    /// Packets skipped because their link layer cannot be analysed.
    pub skipped_unsupported: u64,
    /// Packets skipped because they were internally inconsistent.
    pub skipped_invalid: u64,
    /// The file ended in the middle of a record.
    pub truncated_tail: bool,
}

#[derive(Debug, Clone, Copy)]
struct Interface {
    linktype: u32,
    units_per_sec: u64,
}

pub enum Record {
    Packet(RawPacket),
    /// A packet record that was skipped (unsupported link type or inconsistent).
    Skipped,
}

enum Fill {
    Full,
    Eof,
    Partial,
}

pub struct CaptureFileReader<R: Read + Seek> {
    r: BufReader<R>,
    format: Format,
    big_endian: bool,
    nanos: bool,
    pcap_linktype: u32,
    interfaces: Vec<Interface>,
    offset: u64,
    pub stats: FileStats,
}

fn invalid(offset: u64, reason: impl std::fmt::Display) -> CaptureError {
    CaptureError::InvalidFile(format!("{reason} (at byte {offset})"))
}

impl<R: Read + Seek> CaptureFileReader<R> {
    pub fn new(inner: R) -> Result<Self, CaptureError> {
        let mut r = BufReader::with_capacity(READ_BUFFER, inner);
        let mut magic = [0u8; 4];
        match read_full(&mut r, &mut magic)? {
            Fill::Full => {}
            _ => {
                return Err(CaptureError::InvalidFile(
                    "the file is empty or too short to be a capture".into(),
                ));
            }
        }
        let mut reader = Self {
            r,
            format: Format::Pcap,
            big_endian: false,
            nanos: false,
            pcap_linktype: 0,
            interfaces: Vec::new(),
            offset: 4,
            stats: FileStats::default(),
        };
        match magic {
            [0xd4, 0xc3, 0xb2, 0xa1] => (reader.big_endian, reader.nanos) = (false, false),
            [0xa1, 0xb2, 0xc3, 0xd4] => (reader.big_endian, reader.nanos) = (true, false),
            [0x4d, 0x3c, 0xb2, 0xa1] => (reader.big_endian, reader.nanos) = (false, true),
            [0xa1, 0xb2, 0x3c, 0x4d] => (reader.big_endian, reader.nanos) = (true, true),
            [0x0a, 0x0d, 0x0d, 0x0a] => {
                reader.format = Format::PcapNg;
                let mut len = [0u8; 4];
                if !matches!(read_full(&mut reader.r, &mut len)?, Fill::Full) {
                    return Err(invalid(0, "the PCAPNG section header is incomplete"));
                }
                reader.offset += 4;
                reader.read_section_header(len)?;
                return Ok(reader);
            }
            _ => {
                return Err(CaptureError::InvalidFile(
                    "unrecognised file signature (expected PCAP or PCAPNG)".into(),
                ));
            }
        }
        let mut hdr = [0u8; 20];
        if !matches!(read_full(&mut reader.r, &mut hdr)?, Fill::Full) {
            return Err(invalid(4, "the PCAP header is incomplete"));
        }
        reader.offset += 20;
        let major = reader.u16(&hdr[0..2]);
        if major != 2 {
            return Err(invalid(4, format!("unsupported PCAP version {major}")));
        }
        reader.pcap_linktype = reader.u32(&hdr[16..20]) & 0x0FFF_FFFF;
        if !linktype::is_supported(reader.pcap_linktype) {
            return Err(CaptureError::InvalidFile(format!(
                "link-layer type {} is not supported (supported: Ethernet, Linux cooked, raw IP, loopback)",
                reader.pcap_linktype
            )));
        }
        Ok(reader)
    }

    pub fn format(&self) -> Format {
        self.format
    }

    /// Bytes consumed so far (for progress).
    pub fn bytes_read(&self) -> u64 {
        self.offset
    }

    fn u16(&self, b: &[u8]) -> u16 {
        let a = [b[0], b[1]];
        if self.big_endian {
            u16::from_be_bytes(a)
        } else {
            u16::from_le_bytes(a)
        }
    }

    fn u32(&self, b: &[u8]) -> u32 {
        let a = [b[0], b[1], b[2], b[3]];
        if self.big_endian {
            u32::from_be_bytes(a)
        } else {
            u32::from_le_bytes(a)
        }
    }

    /// Next analysable packet; skipped records are passed over transparently.
    pub fn next_packet(&mut self) -> Result<Option<RawPacket>, CaptureError> {
        loop {
            match self.next_record(true)? {
                None => return Ok(None),
                Some(Record::Packet(p)) => return Ok(Some(p)),
                Some(Record::Skipped) => {}
            }
        }
    }

    /// Reads one packet record. With `want_data == false` payloads are seeked over (used for counting).
    pub fn next_record(&mut self, want_data: bool) -> Result<Option<Record>, CaptureError> {
        match self.format {
            Format::Pcap => self.next_pcap(want_data),
            Format::PcapNg => self.next_pcapng(want_data),
        }
    }

    fn skip(&mut self, n: u64) -> Result<(), CaptureError> {
        let n = i64::try_from(n).map_err(|_| invalid(self.offset, "record too large"))?;
        self.r.seek_relative(n)?;
        self.offset += n as u64;
        Ok(())
    }

    // ---- classic PCAP ----

    fn next_pcap(&mut self, want_data: bool) -> Result<Option<Record>, CaptureError> {
        let mut h = [0u8; 16];
        match read_full(&mut self.r, &mut h)? {
            Fill::Eof => return Ok(None),
            Fill::Partial => {
                self.stats.truncated_tail = true;
                return Ok(None);
            }
            Fill::Full => self.offset += 16,
        }
        let (sec, frac, incl, orig) = (
            self.u32(&h[0..4]),
            self.u32(&h[4..8]),
            self.u32(&h[8..12]),
            self.u32(&h[12..16]),
        );
        if incl > MAX_PACKET_BYTES {
            return Err(invalid(
                self.offset - 16,
                format!("packet of {incl} bytes exceeds the {MAX_PACKET_BYTES} byte limit"),
            ));
        }
        if !want_data {
            return match self.skip_checked(u64::from(incl))? {
                true => Ok(Some(Record::Skipped)),
                false => Ok(None),
            };
        }
        let mut data = vec![0u8; incl as usize];
        if !matches!(read_full(&mut self.r, &mut data)?, Fill::Full) {
            self.stats.truncated_tail = true;
            return Ok(None);
        }
        self.offset += u64::from(incl);
        let frac_micros = if self.nanos { frac / 1000 } else { frac };
        let ts = i64::from(sec) * 1_000_000 + i64::from(frac_micros);
        Ok(Some(self.finish_packet(
            self.pcap_linktype,
            ts,
            &data,
            orig,
        )))
    }

    /// Seeks over `n` bytes; `false` if the file ends before them.
    fn skip_checked(&mut self, n: u64) -> Result<bool, CaptureError> {
        // `seek_relative` doesn't detect EOF, so peek the last byte instead.
        if n == 0 {
            return Ok(true);
        }
        self.skip(n - 1)?;
        let mut last = [0u8; 1];
        match read_full(&mut self.r, &mut last)? {
            Fill::Full => {
                self.offset += 1;
                Ok(true)
            }
            _ => {
                self.stats.truncated_tail = true;
                Ok(false)
            }
        }
    }

    fn finish_packet(
        &mut self,
        linktype: u32,
        ts_micros: i64,
        data: &[u8],
        orig_len: u32,
    ) -> Record {
        let Some(frame) = to_ethernet(linktype, data, self.big_endian) else {
            self.stats.skipped_unsupported += 1;
            return Record::Skipped;
        };
        let delta = frame.len() as i64 - data.len() as i64;
        let original = (i64::from(orig_len) + delta).max(frame.len() as i64);
        self.stats.packets += 1;
        Record::Packet(RawPacket {
            id: 0,
            ts_micros,
            captured_len: frame.len() as u32,
            original_len: u32::try_from(original).unwrap_or(u32::MAX),
            data: frame.into_owned(),
        })
    }

    // ---- PCAPNG ----

    /// Finishes reading a section header block whose type and length field are already consumed.
    /// The byte order of the section comes from the byte-order magic that follows.
    fn read_section_header(&mut self, len_bytes: [u8; 4]) -> Result<(), CaptureError> {
        let start = self.offset - 8;
        let mut bom = [0u8; 4];
        if !matches!(read_full(&mut self.r, &mut bom)?, Fill::Full) {
            return Err(invalid(start, "the PCAPNG section header is incomplete"));
        }
        self.offset += 4;
        self.big_endian = match u32::from_le_bytes(bom) {
            0x1A2B_3C4D => false,
            0x4D3C_2B1A => true,
            _ => return Err(invalid(start, "bad PCAPNG byte-order magic")),
        };
        let len = self.u32(&len_bytes);
        if len < 28 || !len.is_multiple_of(4) || len > MAX_BLOCK_BYTES {
            return Err(invalid(
                start,
                format!("invalid section header length {len}"),
            ));
        }
        self.skip(u64::from(len) - 12)?; // version, section length, options, trailing length
        self.interfaces.clear();
        Ok(())
    }

    fn next_pcapng(&mut self, want_data: bool) -> Result<Option<Record>, CaptureError> {
        loop {
            let mut h = [0u8; 8];
            match read_full(&mut self.r, &mut h)? {
                Fill::Eof => return Ok(None),
                Fill::Partial => {
                    self.stats.truncated_tail = true;
                    return Ok(None);
                }
                Fill::Full => self.offset += 8,
            }
            let start = self.offset - 8;
            if h[0..4] == [0x0a, 0x0d, 0x0d, 0x0a] {
                // A new section: its own byte order and interface table.
                self.read_section_header([h[4], h[5], h[6], h[7]])?;
                continue;
            }
            let (kind, len) = (self.u32(&h[0..4]), self.u32(&h[4..8]));
            if len < 12 || !len.is_multiple_of(4) || len > MAX_BLOCK_BYTES {
                return Err(invalid(start, format!("invalid block length {len}")));
            }
            let is_packet = matches!(kind, 6 | 3 | 2);
            if is_packet && !want_data {
                return match self.skip_checked(u64::from(len) - 8)? {
                    true => Ok(Some(Record::Skipped)),
                    false => Ok(None),
                };
            }
            if !is_packet && kind != 1 {
                if !self.skip_checked(u64::from(len) - 8)? {
                    return Ok(None);
                }
                continue; // name resolution, statistics, custom blocks...
            }
            let mut block = vec![0u8; (len - 8) as usize];
            if !matches!(read_full(&mut self.r, &mut block)?, Fill::Full) {
                self.stats.truncated_tail = true;
                return Ok(None);
            }
            self.offset += u64::from(len) - 8;
            let (body, trailer) = block.split_at(block.len() - 4);
            if self.u32(trailer) != len {
                return Err(invalid(start, "block length does not match its trailer"));
            }
            match kind {
                1 => self.add_interface(body, start)?,
                6 | 3 | 2 => return Ok(Some(self.parse_packet_block(kind, body))),
                _ => {}
            }
        }
    }

    fn add_interface(&mut self, body: &[u8], start: u64) -> Result<(), CaptureError> {
        if body.len() < 8 {
            return Err(invalid(start, "interface description block is too short"));
        }
        let linktype = u32::from(self.u16(&body[0..2]));
        let mut units_per_sec = 1_000_000u64;
        let mut opts = &body[8..];
        while opts.len() >= 4 {
            let (code, olen) = (self.u16(&opts[0..2]), usize::from(self.u16(&opts[2..4])));
            if code == 0 {
                break;
            }
            let padded = olen.div_ceil(4) * 4;
            let Some(value) = opts.get(4..4 + olen) else {
                break;
            };
            if code == 9 && olen == 1 {
                let b = value[0];
                units_per_sec = if b & 0x80 == 0 {
                    10u64.checked_pow(u32::from(b)).unwrap_or(1_000_000)
                } else {
                    1u64.checked_shl(u32::from(b & 0x7f)).unwrap_or(1_000_000)
                };
            }
            opts = opts.get(4 + padded..).unwrap_or(&[]);
        }
        if self.interfaces.len() >= 4096 {
            return Err(invalid(start, "too many interfaces in one section"));
        }
        self.interfaces.push(Interface {
            linktype,
            units_per_sec: units_per_sec.max(1),
        });
        Ok(())
    }

    fn parse_packet_block(&mut self, kind: u32, body: &[u8]) -> Record {
        // (interface id, timestamp units, captured length, original length, data offset)
        let parsed = match kind {
            6 if body.len() >= 20 => Some((
                self.u32(&body[0..4]) as usize,
                (u64::from(self.u32(&body[4..8])) << 32) | u64::from(self.u32(&body[8..12])),
                self.u32(&body[12..16]),
                self.u32(&body[16..20]),
                20,
            )),
            3 if body.len() >= 4 => {
                let orig = self.u32(&body[0..4]);
                Some((0, 0, orig.min((body.len() - 4) as u32), orig, 4))
            }
            2 if body.len() >= 20 => Some((
                usize::from(self.u16(&body[0..2])),
                (u64::from(self.u32(&body[4..8])) << 32) | u64::from(self.u32(&body[8..12])),
                self.u32(&body[12..16]),
                self.u32(&body[16..20]),
                20,
            )),
            _ => None,
        };
        let Some((iface, units, caplen, orig, at)) = parsed else {
            self.stats.skipped_invalid += 1;
            return Record::Skipped;
        };
        let (Some(i), Some(data)) = (
            self.interfaces.get(iface).copied(),
            body.get(at..usize::saturating_add(at, caplen as usize)),
        ) else {
            self.stats.skipped_invalid += 1;
            return Record::Skipped;
        };
        if caplen > MAX_PACKET_BYTES {
            self.stats.skipped_invalid += 1;
            return Record::Skipped;
        }
        let micros = (u128::from(units) * 1_000_000 / u128::from(i.units_per_sec))
            .min(i64::MAX as u128) as i64;
        self.finish_packet(i.linktype, micros, data, orig)
    }
}

/// Reads exactly `buf.len()` bytes unless the stream ends first.
fn read_full<R: Read>(r: &mut R, buf: &mut [u8]) -> Result<Fill, CaptureError> {
    let mut n = 0;
    while n < buf.len() {
        match r.read(&mut buf[n..]) {
            Ok(0) => break,
            Ok(k) => n += k,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e.into()),
        }
    }
    Ok(match n {
        x if x == buf.len() => Fill::Full,
        0 => Fill::Eof,
        _ => Fill::Partial,
    })
}

/// Number of packet records in the file (without reading payloads). Used for progress totals.
pub fn count_packets<R: Read + Seek>(inner: R) -> Result<u64, CaptureError> {
    let mut reader = CaptureFileReader::new(inner)?;
    let mut n = 0u64;
    while reader.next_record(false)?.is_some() {
        n += 1;
    }
    Ok(n)
}

/// Incremental writer for a classic little-endian, microsecond-resolution Ethernet PCAP file.
pub struct PcapWriter<W: Write> {
    w: W,
    pub packets: u64,
}

impl<W: Write> PcapWriter<W> {
    pub fn new(mut w: W) -> io::Result<Self> {
        w.write_all(&[0xd4, 0xc3, 0xb2, 0xa1])?;
        w.write_all(&2u16.to_le_bytes())?;
        w.write_all(&4u16.to_le_bytes())?;
        w.write_all(&0i32.to_le_bytes())?; // thiszone
        w.write_all(&0u32.to_le_bytes())?; // sigfigs
        w.write_all(&MAX_PACKET_BYTES.to_le_bytes())?;
        w.write_all(&1u32.to_le_bytes())?; // Ethernet
        Ok(Self { w, packets: 0 })
    }

    pub fn write(&mut self, p: &RawPacket) -> io::Result<()> {
        let sec = u32::try_from(p.ts_micros.div_euclid(1_000_000).max(0)).unwrap_or(u32::MAX);
        let usec = p.ts_micros.rem_euclid(1_000_000) as u32;
        let data = &p.data[..p.data.len().min(MAX_PACKET_BYTES as usize)];
        self.w.write_all(&sec.to_le_bytes())?;
        self.w.write_all(&usec.to_le_bytes())?;
        self.w.write_all(&(data.len() as u32).to_le_bytes())?;
        self.w
            .write_all(&p.original_len.max(data.len() as u32).to_le_bytes())?;
        self.w.write_all(data)?;
        self.packets += 1;
        Ok(())
    }

    pub fn finish(mut self) -> io::Result<u64> {
        self.w.flush()?;
        Ok(self.packets)
    }
}

/// Convenience wrapper over [`PcapWriter`].
pub fn write_pcap<'a, W: Write>(
    w: W,
    packets: impl Iterator<Item = &'a RawPacket>,
) -> io::Result<u64> {
    let mut writer = PcapWriter::new(w)?;
    for p in packets {
        writer.write(p)?;
    }
    writer.finish()
}

pub fn rewind<R: Seek>(r: &mut R) -> io::Result<()> {
    r.seek(SeekFrom::Start(0)).map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn eth_frame(tag: u8, len: usize) -> Vec<u8> {
        let mut f = vec![0u8; 12];
        f.extend([0x08, 0x00]);
        f.extend(vec![tag; len.saturating_sub(14)]);
        f
    }

    struct Enc {
        be: bool,
    }

    impl Enc {
        fn u16(&self, v: u16) -> [u8; 2] {
            if self.be {
                v.to_be_bytes()
            } else {
                v.to_le_bytes()
            }
        }
        fn u32(&self, v: u32) -> [u8; 4] {
            if self.be {
                v.to_be_bytes()
            } else {
                v.to_le_bytes()
            }
        }
    }

    fn pcap(be: bool, nanos: bool, linktype: u32, packets: &[(u32, u32, Vec<u8>, u32)]) -> Vec<u8> {
        let e = Enc { be };
        let magic: [u8; 4] = match (be, nanos) {
            (false, false) => [0xd4, 0xc3, 0xb2, 0xa1],
            (true, false) => [0xa1, 0xb2, 0xc3, 0xd4],
            (false, true) => [0x4d, 0x3c, 0xb2, 0xa1],
            (true, true) => [0xa1, 0xb2, 0x3c, 0x4d],
        };
        let mut v = magic.to_vec();
        v.extend(e.u16(2));
        v.extend(e.u16(4));
        v.extend(e.u32(0));
        v.extend(e.u32(0));
        v.extend(e.u32(65535));
        v.extend(e.u32(linktype));
        for (sec, frac, data, orig) in packets {
            v.extend(e.u32(*sec));
            v.extend(e.u32(*frac));
            v.extend(e.u32(data.len() as u32));
            v.extend(e.u32(*orig));
            v.extend(data);
        }
        v
    }

    fn block(e: &Enc, kind: u32, body: &[u8]) -> Vec<u8> {
        let padded = body.len().div_ceil(4) * 4;
        let len = (12 + padded) as u32;
        let mut v = e.u32(kind).to_vec();
        v.extend(e.u32(len));
        v.extend(body);
        v.extend(vec![0u8; padded - body.len()]);
        v.extend(e.u32(len));
        v
    }

    fn shb(e: &Enc) -> Vec<u8> {
        let mut body = e.u32(0x1A2B_3C4D).to_vec();
        body.extend(e.u16(1));
        body.extend(e.u16(0));
        body.extend((-1i64).to_le_bytes()); // section length: unspecified
        block(e, 0x0A0D_0D0A, &body)
    }

    fn idb(e: &Enc, linktype: u16, tsresol: Option<u8>) -> Vec<u8> {
        let mut body = e.u16(linktype).to_vec();
        body.extend(e.u16(0));
        body.extend(e.u32(65535));
        if let Some(r) = tsresol {
            body.extend(e.u16(9));
            body.extend(e.u16(1));
            body.extend([r, 0, 0, 0]);
            body.extend(e.u16(0));
            body.extend(e.u16(0));
        }
        block(e, 1, &body)
    }

    fn epb(e: &Enc, iface: u32, units: u64, data: &[u8], orig: u32) -> Vec<u8> {
        let mut body = e.u32(iface).to_vec();
        body.extend(e.u32((units >> 32) as u32));
        body.extend(e.u32(units as u32));
        body.extend(e.u32(data.len() as u32));
        body.extend(e.u32(orig));
        body.extend(data);
        block(e, 6, &body)
    }

    fn read_all(bytes: Vec<u8>) -> Result<(Vec<RawPacket>, FileStats), CaptureError> {
        let mut r = CaptureFileReader::new(Cursor::new(bytes))?;
        let mut out = vec![];
        while let Some(p) = r.next_packet()? {
            out.push(p);
        }
        Ok((out, r.stats.clone()))
    }

    #[test]
    fn reads_little_endian_pcap_with_timestamps() {
        let f = eth_frame(1, 60);
        let (pk, st) = read_all(pcap(
            false,
            false,
            1,
            &[
                (1_700_000_000, 250_000, f.clone(), 60),
                (1_700_000_001, 5, eth_frame(2, 100), 1500),
            ],
        ))
        .unwrap();
        assert_eq!(pk.len(), 2);
        assert_eq!(pk[0].ts_micros, 1_700_000_000_250_000);
        assert_eq!(pk[0].data, f);
        assert_eq!((pk[1].captured_len, pk[1].original_len), (100, 1500));
        assert_eq!(st.packets, 2);
        assert!(!st.truncated_tail);
    }

    #[test]
    fn reads_big_endian_and_nanosecond_pcap() {
        let (pk, _) = read_all(pcap(true, false, 1, &[(10, 7, eth_frame(1, 60), 60)])).unwrap();
        assert_eq!(pk[0].ts_micros, 10_000_007);
        let (pk, _) = read_all(pcap(false, true, 1, &[(10, 7_000, eth_frame(1, 60), 60)])).unwrap();
        assert_eq!(pk[0].ts_micros, 10_000_007);
        let (pk, _) = read_all(pcap(
            true,
            true,
            1,
            &[(10, 123_456_789, eth_frame(1, 60), 60)],
        ))
        .unwrap();
        assert_eq!(pk[0].ts_micros, 10_123_456);
    }

    #[test]
    fn converts_other_link_layers() {
        let mut sll = vec![0, 0, 0, 1, 0, 6, 1, 2, 3, 4, 5, 6, 0, 0, 0x08, 0x00];
        sll.extend([
            0x45, 0, 0, 20, 0, 0, 0, 0, 64, 6, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2,
        ]);
        let (pk, _) = read_all(pcap(
            false,
            false,
            113,
            &[(1, 0, sll.clone(), sll.len() as u32)],
        ))
        .unwrap();
        assert_eq!(pk[0].data.len(), sll.len() - 16 + 14);
        assert_eq!(&pk[0].data[12..14], &[0x08, 0x00]);
        assert_eq!(pk[0].original_len as usize, pk[0].data.len());
    }

    #[test]
    fn rejects_unsupported_link_type_up_front() {
        let e = read_all(pcap(false, false, 147, &[])).err().unwrap();
        assert!(matches!(e, CaptureError::InvalidFile(m) if m.contains("147")));
    }

    #[test]
    fn rejects_non_captures() {
        for bytes in [
            vec![],
            vec![1, 2, 3],
            b"hello world, not a capture".to_vec(),
            vec![0xd4, 0xc3, 0xb2, 0xa1, 2, 0],
        ] {
            assert!(matches!(read_all(bytes), Err(CaptureError::InvalidFile(_))));
        }
        let mut bad_version = pcap(false, false, 1, &[]);
        bad_version[4] = 9;
        assert!(
            matches!(read_all(bad_version), Err(CaptureError::InvalidFile(m)) if m.contains("version"))
        );
    }

    #[test]
    fn oversized_packet_lengths_are_rejected_not_allocated() {
        let mut bytes = pcap(false, false, 1, &[(1, 0, eth_frame(1, 60), 60)]);
        bytes[24 + 8..24 + 12].copy_from_slice(&0xFFFF_FFF0u32.to_le_bytes());
        let e = read_all(bytes).err().unwrap();
        assert!(matches!(e, CaptureError::InvalidFile(m) if m.contains("exceeds")));
    }

    #[test]
    fn truncated_tail_keeps_complete_packets() {
        let full = pcap(
            false,
            false,
            1,
            &[(1, 0, eth_frame(1, 60), 60), (2, 0, eth_frame(2, 60), 60)],
        );
        for cut in [3, 20, 40] {
            let (pk, st) = read_all(full[..full.len() - cut].to_vec()).unwrap();
            assert_eq!(pk.len(), 1, "cut {cut}");
            assert!(st.truncated_tail);
        }
        let (pk, st) = read_all(full[..24 + 16].to_vec()).unwrap(); // header of packet 1, no data
        assert!(pk.is_empty() && st.truncated_tail);
    }

    #[test]
    fn reads_pcapng_with_interfaces_and_resolution() {
        let e = Enc { be: false };
        let mut f = shb(&e);
        f.extend(idb(&e, 1, None)); // µs
        f.extend(idb(&e, 1, Some(9))); // ns
        f.extend(epb(&e, 0, 1_700_000_000_250_000, &eth_frame(1, 61), 61)); // odd length → padded
        f.extend(epb(&e, 1, 1_700_000_000_250_000_000, &eth_frame(2, 60), 60));
        f.extend(block(&e, 5, &[0u8; 16])); // statistics block: skipped
        let (pk, st) = read_all(f).unwrap();
        assert_eq!(pk.len(), 2);
        assert_eq!(pk[0].ts_micros, 1_700_000_000_250_000);
        assert_eq!(pk[1].ts_micros, 1_700_000_000_250_000);
        assert_eq!(pk[0].data.len(), 61);
        assert_eq!(st.packets, 2);
    }

    #[test]
    fn reads_big_endian_pcapng_and_simple_packet_blocks() {
        let e = Enc { be: true };
        let mut f = shb(&e);
        f.extend(idb(&e, 1, Some(0x80 | 10))); // 2^-10 s units
        let mut spb = e.u32(60).to_vec();
        spb.extend(eth_frame(7, 60));
        f.extend(block(&e, 3, &spb));
        f.extend(epb(&e, 0, 2048, &eth_frame(1, 60), 60)); // 2 seconds in 2^-10 units
        let (pk, _) = read_all(f).unwrap();
        assert_eq!(pk.len(), 2);
        assert_eq!(pk[0].ts_micros, 0);
        assert_eq!(pk[1].ts_micros, 2_000_000);
    }

    #[test]
    fn pcapng_sections_reset_interfaces_and_byte_order() {
        let (le, be) = (Enc { be: false }, Enc { be: true });
        let mut f = shb(&le);
        f.extend(idb(&le, 1, None));
        f.extend(epb(&le, 0, 1_000_000, &eth_frame(1, 60), 60));
        f.extend(shb(&be));
        f.extend(idb(&be, 1, None));
        f.extend(epb(&be, 0, 2_000_000, &eth_frame(2, 60), 60));
        let (pk, _) = read_all(f.clone()).unwrap();
        assert_eq!(
            pk.iter().map(|p| p.ts_micros).collect::<Vec<_>>(),
            vec![1_000_000, 2_000_000]
        );
        // referencing an interface that the new section never declared is skipped, not trusted
        let mut g = shb(&le);
        g.extend(idb(&le, 1, None));
        g.extend(shb(&le));
        g.extend(epb(&le, 0, 5, &eth_frame(1, 60), 60));
        let (pk, st) = read_all(g).unwrap();
        assert!(pk.is_empty());
        assert_eq!(st.skipped_invalid, 1);
    }

    #[test]
    fn pcapng_skips_unsupported_interfaces_and_bad_references() {
        let e = Enc { be: false };
        let mut f = shb(&e);
        f.extend(idb(&e, 147, None));
        f.extend(idb(&e, 1, None));
        f.extend(epb(&e, 0, 1, &eth_frame(1, 60), 60)); // unsupported link type
        f.extend(epb(&e, 9, 1, &eth_frame(1, 60), 60)); // unknown interface
        f.extend(epb(&e, 1, 1, &eth_frame(1, 60), 60));
        let (pk, st) = read_all(f).unwrap();
        assert_eq!(pk.len(), 1);
        assert_eq!((st.skipped_unsupported, st.skipped_invalid), (1, 1));
    }

    #[test]
    fn pcapng_block_validation() {
        let e = Enc { be: false };
        let mut f = shb(&e);
        f.extend(idb(&e, 1, None));
        let mut bad_trailer = epb(&e, 0, 1, &eth_frame(1, 60), 60);
        let n = bad_trailer.len();
        bad_trailer[n - 4] ^= 0xff;
        let mut g = f.clone();
        g.extend(bad_trailer);
        assert!(matches!(read_all(g), Err(CaptureError::InvalidFile(m)) if m.contains("trailer")));
        let mut h = f.clone();
        h.extend(e.u32(6));
        h.extend(e.u32(0xFFFF_FFF0)); // absurd block length
        assert!(
            matches!(read_all(h), Err(CaptureError::InvalidFile(m)) if m.contains("block length"))
        );
        let mut k = f;
        k.extend(e.u32(6));
        k.extend(e.u32(10)); // not a multiple of 4
        assert!(matches!(read_all(k), Err(CaptureError::InvalidFile(_))));
    }

    #[test]
    fn counting_matches_reading_for_both_formats() {
        let pcap_file = pcap(
            false,
            false,
            1,
            &(0..50)
                .map(|i| (i, 0, eth_frame(1, 60 + i as usize), 100))
                .collect::<Vec<_>>(),
        );
        assert_eq!(count_packets(Cursor::new(pcap_file.clone())).unwrap(), 50);
        assert_eq!(read_all(pcap_file).unwrap().0.len(), 50);
        let e = Enc { be: false };
        let mut ng = shb(&e);
        ng.extend(idb(&e, 1, None));
        for i in 0..50 {
            ng.extend(epb(&e, 0, i, &eth_frame(1, 60 + i as usize), 100));
            if i % 10 == 0 {
                ng.extend(block(&e, 5, &[0u8; 8]));
            }
        }
        assert_eq!(count_packets(Cursor::new(ng.clone())).unwrap(), 50);
        assert_eq!(read_all(ng).unwrap().0.len(), 50);
    }

    #[test]
    fn writer_round_trips_through_the_reader() {
        let packets: Vec<RawPacket> = (0..20)
            .map(|i| RawPacket {
                id: i + 1,
                ts_micros: 1_700_000_000_000_000 + i as i64 * 1234,
                captured_len: 60,
                original_len: 1500,
                data: eth_frame(i as u8, 60),
            })
            .collect();
        let mut buf = Vec::new();
        assert_eq!(write_pcap(&mut buf, packets.iter()).unwrap(), 20);
        let (back, _) = read_all(buf).unwrap();
        assert_eq!(back.len(), 20);
        for (a, b) in packets.iter().zip(&back) {
            assert_eq!(
                (a.ts_micros, &a.data, a.original_len),
                (b.ts_micros, &b.data, b.original_len)
            );
        }
    }

    #[test]
    fn writer_handles_odd_timestamps() {
        let p = RawPacket {
            id: 1,
            ts_micros: -5,
            captured_len: 14,
            original_len: 3,
            data: eth_frame(0, 14),
        };
        let mut buf = Vec::new();
        write_pcap(&mut buf, std::iter::once(&p)).unwrap();
        let (back, _) = read_all(buf).unwrap();
        assert_eq!(back[0].ts_micros, 999_995); // negative seconds clamp to 0
        assert!(back[0].original_len >= back[0].captured_len);
    }

    #[test]
    fn corrupted_files_never_panic() {
        let e = Enc { be: false };
        let mut ng = shb(&e);
        ng.extend(idb(&e, 1, Some(9)));
        for i in 0..4 {
            ng.extend(epb(&e, 0, i, &eth_frame(1, 60), 60));
        }
        let classic = pcap(
            false,
            false,
            1,
            &(0..4)
                .map(|i| (i, 0, eth_frame(1, 60), 60))
                .collect::<Vec<_>>(),
        );
        for base in [ng, classic] {
            for i in 0..base.len() {
                for v in [0u8, 1, 0x7f, 0x80, 0xff] {
                    let mut m = base.clone();
                    m[i] = v;
                    let _ = read_all(m.clone());
                    let _ = count_packets(Cursor::new(m));
                }
            }
            for n in 0..base.len() {
                let _ = read_all(base[..n].to_vec());
            }
        }
    }
}
