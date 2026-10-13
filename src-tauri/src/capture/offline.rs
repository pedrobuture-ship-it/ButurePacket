//! Streams a capture file through a sink in batches, with progress and cancellation.
//! The file is never held in memory: packets are read, batched and handed on.

use std::fs::{self, File};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use serde::Serialize;

use super::error::CaptureError;
use super::file::{CaptureFileReader, count_packets};
use super::packet::RawPacket;

const BATCH_SIZE: usize = 2_000;
const PROGRESS_INTERVAL: Duration = Duration::from_millis(100);

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum Phase {
    Counting,
    Parsing,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Progress {
    pub phase: Phase,
    /// Packet records handled so far.
    pub processed: u64,
    /// Packet records in the file (0 until counted).
    pub total: u64,
    pub bytes_read: u64,
    pub file_bytes: u64,
}

pub trait OfflineSink {
    fn progress(&self, p: &Progress);
    fn batch(&self, packets: Vec<RawPacket>);
}

#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct OfflineOutcome {
    pub packets: u64,
    pub skipped_unsupported: u64,
    pub skipped_invalid: u64,
    pub truncated_tail: bool,
    pub cancelled: bool,
}

/// Accepts only an existing, non-empty, regular file (following symlinks the user picked,
/// rejecting directories, devices, FIFOs and sockets). Returns the canonical path.
pub fn validate_input_path(path: &Path) -> Result<PathBuf, CaptureError> {
    let canonical = fs::canonicalize(path).map_err(|e| match e.kind() {
        std::io::ErrorKind::NotFound => {
            CaptureError::Io(format!("'{}' does not exist.", path.display()))
        }
        std::io::ErrorKind::PermissionDenied => {
            CaptureError::Io(format!("Permission denied reading '{}'.", path.display()))
        }
        _ => CaptureError::Io(e.to_string()),
    })?;
    let meta = fs::metadata(&canonical)?;
    if !meta.is_file() {
        return Err(CaptureError::InvalidFile(
            "only regular files can be opened".into(),
        ));
    }
    if meta.len() == 0 {
        return Err(CaptureError::InvalidFile("the file is empty".into()));
    }
    Ok(canonical)
}

pub fn run(
    path: &Path,
    cancel: &AtomicBool,
    sink: &dyn OfflineSink,
) -> Result<OfflineOutcome, CaptureError> {
    let path = validate_input_path(path)?;
    let file_bytes = fs::metadata(&path)?.len();
    let mut progress = Progress {
        phase: Phase::Counting,
        processed: 0,
        total: 0,
        bytes_read: 0,
        file_bytes,
    };
    sink.progress(&progress);
    let total = count_packets(File::open(&path)?)?;
    if cancel.load(Ordering::Relaxed) {
        return Ok(OfflineOutcome {
            cancelled: true,
            ..Default::default()
        });
    }
    progress.phase = Phase::Parsing;
    progress.total = total;
    sink.progress(&progress);

    let mut reader = CaptureFileReader::new(File::open(&path)?)?;
    let mut batch: Vec<RawPacket> = Vec::with_capacity(BATCH_SIZE);
    let mut next_id = 1u64;
    let mut last_report = Instant::now();
    let mut cancelled = false;
    loop {
        let packet = reader.next_packet()?;
        let done = packet.is_none();
        if let Some(mut p) = packet {
            p.id = next_id;
            next_id += 1;
            batch.push(p);
        }
        if batch.len() >= BATCH_SIZE || (done && !batch.is_empty()) {
            sink.batch(std::mem::replace(
                &mut batch,
                Vec::with_capacity(BATCH_SIZE),
            ));
            // Give the UI thread room to breathe on very large files.
            std::thread::sleep(Duration::from_millis(1));
            if cancel.load(Ordering::Relaxed) && !done {
                cancelled = true;
                break;
            }
        }
        if last_report.elapsed() >= PROGRESS_INTERVAL || done {
            let s = &reader.stats;
            progress.processed = s.packets + s.skipped_unsupported + s.skipped_invalid;
            progress.bytes_read = reader.bytes_read();
            sink.progress(&progress);
            last_report = Instant::now();
        }
        if done {
            break;
        }
    }
    let s = reader.stats;
    Ok(OfflineOutcome {
        packets: s.packets,
        skipped_unsupported: s.skipped_unsupported,
        skipped_invalid: s.skipped_invalid,
        truncated_tail: s.truncated_tail,
        cancelled,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capture::file::write_pcap;
    use std::sync::Mutex;

    #[derive(Default)]
    struct Collect {
        batches: Mutex<Vec<Vec<RawPacket>>>,
        progress: Mutex<Vec<Progress>>,
        cancel_after_first_batch: Option<&'static AtomicBool>,
    }

    impl OfflineSink for Collect {
        fn progress(&self, p: &Progress) {
            self.progress.lock().unwrap().push(p.clone());
        }
        fn batch(&self, packets: Vec<RawPacket>) {
            self.batches.lock().unwrap().push(packets);
            if let Some(c) = self.cancel_after_first_batch {
                c.store(true, Ordering::Relaxed);
            }
        }
    }

    fn write_capture(dir: &Path, n: usize) -> PathBuf {
        let packets: Vec<RawPacket> = (0..n)
            .map(|i| {
                let mut data = vec![0u8; 12];
                data.extend([0x08, 0x00]);
                data.extend(vec![i as u8; 46]);
                RawPacket {
                    id: 0,
                    ts_micros: 1_000_000 * i as i64,
                    captured_len: 60,
                    original_len: 60,
                    data,
                }
            })
            .collect();
        let path = dir.join("test.pcap");
        let f = File::create(&path).unwrap();
        write_pcap(f, packets.iter()).unwrap();
        path
    }

    #[test]
    fn streams_all_packets_in_batches_with_sequential_ids() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_capture(dir.path(), 4_500);
        let sink = Collect::default();
        let out = run(&path, &AtomicBool::new(false), &sink).unwrap();
        assert_eq!(
            (out.packets, out.cancelled, out.truncated_tail),
            (4_500, false, false)
        );
        let batches = sink.batches.lock().unwrap();
        assert_eq!(
            batches.iter().map(Vec::len).collect::<Vec<_>>(),
            vec![2_000, 2_000, 500]
        );
        let ids: Vec<u64> = batches.iter().flatten().map(|p| p.id).collect();
        assert_eq!(ids, (1..=4_500).collect::<Vec<_>>());
        let progress = sink.progress.lock().unwrap();
        assert_eq!(progress[0].phase, Phase::Counting);
        assert_eq!(progress[1].total, 4_500);
        let last = progress.last().unwrap();
        assert_eq!(
            (last.phase, last.processed, last.total),
            (Phase::Parsing, 4_500, 4_500)
        );
        assert_eq!(last.bytes_read, last.file_bytes);
    }

    #[test]
    fn cancellation_stops_early_and_is_reported() {
        static CANCEL: AtomicBool = AtomicBool::new(false);
        let dir = tempfile::tempdir().unwrap();
        let path = write_capture(dir.path(), 10_000);
        let sink = Collect {
            cancel_after_first_batch: Some(&CANCEL),
            ..Default::default()
        };
        let out = run(&path, &CANCEL, &sink).unwrap();
        assert!(out.cancelled);
        assert!(out.packets < 10_000);
    }

    #[test]
    fn rejects_bad_paths() {
        let dir = tempfile::tempdir().unwrap();
        let sink = Collect::default();
        let no = AtomicBool::new(false);
        assert!(
            matches!(run(&dir.path().join("missing.pcap"), &no, &sink), Err(CaptureError::Io(m)) if m.contains("does not exist"))
        );
        assert!(
            matches!(run(dir.path(), &no, &sink), Err(CaptureError::InvalidFile(m)) if m.contains("regular"))
        );
        let empty = dir.path().join("empty.pcap");
        File::create(&empty).unwrap();
        assert!(
            matches!(run(&empty, &no, &sink), Err(CaptureError::InvalidFile(m)) if m.contains("empty"))
        );
        let junk = dir.path().join("junk.pcap");
        fs::write(&junk, b"definitely not a pcap file at all").unwrap();
        assert!(matches!(
            run(&junk, &no, &sink),
            Err(CaptureError::InvalidFile(_))
        ));
        assert!(sink.batches.lock().unwrap().is_empty());
    }

    #[test]
    #[cfg(unix)]
    fn follows_symlinks_to_regular_files_only() {
        let dir = tempfile::tempdir().unwrap();
        let real = write_capture(dir.path(), 3);
        let link = dir.path().join("link.pcap");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let out = run(&link, &AtomicBool::new(false), &Collect::default()).unwrap();
        assert_eq!(out.packets, 3);
        let dir_link = dir.path().join("dirlink");
        std::os::unix::fs::symlink(dir.path(), &dir_link).unwrap();
        assert!(validate_input_path(&dir_link).is_err());
    }

    #[test]
    fn damaged_files_report_what_was_readable() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_capture(dir.path(), 5);
        let bytes = fs::read(&path).unwrap();
        fs::write(&path, &bytes[..bytes.len() - 10]).unwrap();
        let out = run(&path, &AtomicBool::new(false), &Collect::default()).unwrap();
        assert_eq!(out.packets, 4);
        assert!(out.truncated_tail);
    }
}
