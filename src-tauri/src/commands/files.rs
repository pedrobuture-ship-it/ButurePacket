//! Opening and saving capture files.

use std::fs;
use std::io::BufWriter;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Instant;

use serde::Serialize;
use tauri::{AppHandle, Emitter, Manager, State};

use super::capture::{CaptureState, emit_processed};
use super::error::IpcError;
use crate::capture::file::PcapWriter;
use crate::capture::offline::{self, OfflineSink, Progress};
use crate::capture::{CaptureError, RawPacket, SessionState, StatsSnapshot};
use crate::pipeline::Pipeline;

/// Packet rows streamed to the UI per opened file. Flows, DNS, events and analytics always cover the
/// whole file; only the packet list is capped to keep the UI responsive.
pub const MAX_PACKET_ROWS: u64 = 1_000_000;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProgressPayload {
    #[serde(flatten)]
    progress: Option<Progress>,
    file_name: String,
    done: bool,
    cancelled: bool,
    error: Option<IpcError>,
    /// The packet list was cut off at `MAX_PACKET_ROWS`.
    rows_truncated: bool,
    /// The file ended in the middle of a packet.
    truncated_tail: bool,
    skipped: u64,
}

struct FileSink {
    app: AppHandle,
    pipeline: Arc<Pipeline>,
    file_name: String,
    sent_rows: AtomicU64,
    packets: AtomicU64,
    bytes: AtomicU64,
    first_ts: Mutex<Option<i64>>,
    last_ts: AtomicU64,
    last_analytics: Mutex<Instant>,
}

impl FileSink {
    fn payload(&self, progress: Option<Progress>) -> ProgressPayload {
        ProgressPayload {
            progress,
            file_name: self.file_name.clone(),
            done: false,
            cancelled: false,
            error: None,
            rows_truncated: self.sent_rows.load(Ordering::Relaxed) >= MAX_PACKET_ROWS,
            truncated_tail: false,
            skipped: 0,
        }
    }
}

impl OfflineSink for FileSink {
    fn progress(&self, p: &Progress) {
        let _ = self
            .app
            .emit("capture://progress", self.payload(Some(p.clone())));
    }

    fn batch(&self, packets: Vec<RawPacket>) {
        let n = packets.len() as u64;
        let bytes: u64 = packets.iter().map(|p| u64::from(p.captured_len)).sum();
        let (first, last) = (
            packets.first().map(|p| p.ts_micros),
            packets.last().map(|p| p.ts_micros),
        );
        let mut out = self.pipeline.process(packets);
        let room =
            usize::try_from(MAX_PACKET_ROWS.saturating_sub(self.sent_rows.load(Ordering::Relaxed)))
                .unwrap_or(usize::MAX);
        if out.packets.len() > room {
            // Only the first MAX_PACKET_ROWS reach the UI; the database still gets every row.
            out.packets = Arc::new(out.packets[..room].to_vec());
        }
        self.sent_rows
            .fetch_add(out.packets.len() as u64, Ordering::Relaxed);
        emit_processed(&self.app, out);

        let total_packets = self.packets.fetch_add(n, Ordering::Relaxed) + n;
        let total_bytes = self.bytes.fetch_add(bytes, Ordering::Relaxed) + bytes;
        let mut first_ts = self.first_ts.lock().unwrap();
        let start = *first_ts.get_or_insert(first.unwrap_or(0));
        if let Some(l) = last {
            self.last_ts
                .fetch_max(u64::try_from(l.max(0)).unwrap_or(0), Ordering::Relaxed);
        }
        let span_ms = (i64::try_from(self.last_ts.load(Ordering::Relaxed)).unwrap_or(0) - start)
            .max(0)
            / 1000;
        let _ = self.app.emit(
            "capture://stats",
            StatsSnapshot {
                packets: total_packets,
                bytes: total_bytes,
                duration_ms: u64::try_from(span_ms).unwrap_or(0),
                parser_load: 1.0,
                ..Default::default()
            },
        );
        let mut last = self.last_analytics.lock().unwrap();
        if last.elapsed() >= std::time::Duration::from_secs(1) {
            *last = Instant::now();
            let _ = self
                .app
                .emit("capture://analytics", self.pipeline.analytics(true));
            super::storage::emit_status(&self.app, &self.pipeline);
        }
    }
}

fn busy(state: &CaptureState) -> bool {
    state.offline_running.load(Ordering::SeqCst) || state.live_active()
}

#[tauri::command]
pub fn open_capture(
    app: AppHandle,
    state: State<'_, CaptureState>,
    path: String,
) -> Result<(), IpcError> {
    if busy(&state) {
        return Err(CaptureError::Busy(
            "Stop the current capture or wait for the open file to finish before opening another."
                .into(),
        )
        .into());
    }
    let path = PathBuf::from(path);
    let validated = offline::validate_input_path(&path)?;
    let file_name = validated
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();

    state.pipeline.clear();
    state.offline_mode.store(true, Ordering::SeqCst);
    super::storage::attach(&app, &state, false, &file_name);
    let cancel = Arc::new(AtomicBool::new(false));
    *state.offline_cancel.lock().unwrap() = Some(cancel.clone());
    state.offline_running.store(true, Ordering::SeqCst);

    let pipeline = state.pipeline.clone();
    let running = state.offline_running.clone();
    std::thread::Builder::new()
        .name("open-capture".into())
        .spawn(move || {
            let sink = FileSink {
                app: app.clone(),
                pipeline: pipeline.clone(),
                file_name,
                sent_rows: AtomicU64::new(0),
                packets: AtomicU64::new(0),
                bytes: AtomicU64::new(0),
                first_ts: Mutex::new(None),
                last_ts: AtomicU64::new(0),
                last_analytics: Mutex::new(Instant::now()),
            };
            let result = offline::run(&validated, &cancel, &sink);
            let _ = app.emit("capture://analytics", pipeline.analytics(true));
            let mut done = sink.payload(None);
            done.done = true;
            match result {
                Ok(o) => {
                    done.cancelled = o.cancelled;
                    done.truncated_tail = o.truncated_tail;
                    done.skipped = o.skipped_unsupported + o.skipped_invalid;
                }
                Err(e) => done.error = Some(e.into()),
            }
            let _ = app.emit("capture://progress", done);
            let state = app.state::<CaptureState>();
            super::storage::detach(&app, &state);
            let _ = app.emit(
                "capture://state",
                super::capture::state_payload(SessionState::Stopped),
            );
            running.store(false, Ordering::SeqCst);
        })
        .map_err(|e| IpcError::from(CaptureError::Io(e.to_string())))?;
    Ok(())
}

#[tauri::command]
pub fn cancel_open(state: State<'_, CaptureState>) {
    if let Some(c) = state.offline_cancel.lock().unwrap().as_ref() {
        c.store(true, Ordering::SeqCst);
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SaveResult {
    packets: u64,
    /// Older packets had already been dropped from memory and are not in the file.
    evicted: bool,
}

/// Refuses anything but a normal destination: parent directory must exist, and an existing target
/// must be a regular file (never a symlink, which could redirect the write somewhere unexpected).
pub fn validate_output_path(path: &Path) -> Result<(), CaptureError> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    if !parent.is_dir() {
        return Err(CaptureError::Io(format!(
            "The folder '{}' does not exist.",
            parent.display()
        )));
    }
    if path.file_name().is_none() {
        return Err(CaptureError::Io(
            "Choose a file name for the capture.".into(),
        ));
    }
    match fs::symlink_metadata(path) {
        Ok(m) if m.file_type().is_symlink() => Err(CaptureError::Io(
            "Refusing to overwrite a symbolic link.".into(),
        )),
        Ok(m) if !m.is_file() => Err(CaptureError::Io(
            "The destination is not a regular file.".into(),
        )),
        _ => Ok(()),
    }
}

pub fn save_packets(pipeline: &Pipeline, path: &Path) -> Result<SaveResult, CaptureError> {
    validate_output_path(path)?;
    let tmp = path.with_extension(format!("tmp-{}", std::process::id()));
    let result = (|| {
        let file = fs::File::create(&tmp)?;
        let mut writer = PcapWriter::new(BufWriter::new(file))?;
        let mut next = 0u64;
        let mut evicted = false;
        loop {
            let chunk = {
                let store = pipeline.store.lock().unwrap();
                if next == 0 {
                    evicted = store.first_id().is_some_and(|f| f > 1);
                    next = store.first_id().unwrap_or(1);
                }
                store.chunk(next, 4_096)
            };
            let Some(last) = chunk.last().map(|p| p.id) else {
                break;
            };
            for p in &chunk {
                writer.write(p)?;
            }
            next = last + 1;
        }
        let packets = writer.finish()?;
        fs::rename(&tmp, path)?;
        Ok(SaveResult { packets, evicted })
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result
}

#[tauri::command]
pub fn save_capture(state: State<'_, CaptureState>, path: String) -> Result<SaveResult, IpcError> {
    save_packets(&state.pipeline, Path::new(&path)).map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capture::file::CaptureFileReader;

    fn raw(id: u64) -> RawPacket {
        let mut data = vec![0u8; 12];
        data.extend([0x08, 0x00]);
        data.extend(vec![id as u8; 46]);
        RawPacket {
            id,
            ts_micros: id as i64 * 1000,
            captured_len: 60,
            original_len: 60,
            data,
        }
    }

    fn pipeline_with(ids: impl Iterator<Item = u64>) -> Pipeline {
        let p = Pipeline::default();
        let mut store = p.store.lock().unwrap();
        ids.for_each(|i| store.push(raw(i)));
        drop(store);
        p
    }

    #[test]
    fn saves_every_retained_packet_in_order() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("out.pcap");
        let r = save_packets(&pipeline_with(1..=10_000), &path).unwrap();
        assert_eq!((r.packets, r.evicted), (10_000, false));
        let mut reader = CaptureFileReader::new(fs::File::open(&path).unwrap()).unwrap();
        let mut n = 0;
        let mut last_ts = 0;
        while let Some(p) = reader.next_packet().unwrap() {
            assert!(p.ts_micros >= last_ts);
            last_ts = p.ts_micros;
            n += 1;
        }
        assert_eq!(n, 10_000);
        // no temp file is left behind
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
    }

    #[test]
    fn reports_when_older_packets_were_evicted() {
        let dir = tempfile::tempdir().unwrap();
        let r = save_packets(&pipeline_with(500..=520), &dir.path().join("o.pcap")).unwrap();
        assert_eq!((r.packets, r.evicted), (21, true));
    }

    #[test]
    fn saving_an_empty_capture_writes_a_valid_header_only_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("empty.pcap");
        assert_eq!(
            save_packets(&Pipeline::default(), &path).unwrap().packets,
            0
        );
        assert_eq!(fs::metadata(&path).unwrap().len(), 24);
    }

    #[test]
    fn output_path_validation() {
        let dir = tempfile::tempdir().unwrap();
        assert!(validate_output_path(&dir.path().join("ok.pcap")).is_ok());
        assert!(
            matches!(validate_output_path(&dir.path().join("missing/dir/x.pcap")), Err(CaptureError::Io(m)) if m.contains("does not exist"))
        );
        assert!(validate_output_path(dir.path()).is_err()); // a directory is not a file
        #[cfg(unix)]
        {
            let target = dir.path().join("target");
            fs::write(&target, b"precious").unwrap();
            let link = dir.path().join("link.pcap");
            std::os::unix::fs::symlink(&target, &link).unwrap();
            assert!(
                matches!(validate_output_path(&link), Err(CaptureError::Io(m)) if m.contains("symbolic link"))
            );
            assert_eq!(fs::read(&target).unwrap(), b"precious");
        }
    }

    #[test]
    fn overwrites_an_existing_regular_file_atomically() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("o.pcap");
        fs::write(&path, b"old").unwrap();
        save_packets(&pipeline_with(1..=3), &path).unwrap();
        assert!(fs::metadata(&path).unwrap().len() > 24);
    }
}
