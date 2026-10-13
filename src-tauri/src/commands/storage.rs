//! Wiring between capture sessions and the SQLite writer, plus read-only database queries.

use crate::util::LockRecover;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;
use tauri::{AppHandle, Emitter, State};

use super::capture::CaptureState;
use super::error::IpcError;
use crate::capture::CaptureError;
use crate::pipeline::Pipeline;
use crate::storage::database::Database;
use crate::storage::packets::{PacketQuery, count_packets, query_packets};
use crate::storage::writer::{StorageConfig, StorageStatus};

pub const SCRATCH_DIR: &str = "scratch";

/// Removes leftover scratch databases (and their WAL/SHM files) from earlier runs.
pub fn clean_scratch(data_dir: &Path) {
    let dir = data_dir.join(SCRATCH_DIR);
    if let Ok(entries) = fs::read_dir(&dir) {
        for e in entries.flatten() {
            let name = e.file_name();
            if name.to_string_lossy().starts_with("session-") {
                let _ = fs::remove_file(e.path());
            }
        }
    }
}

fn new_session_path(data_dir: &Path, kind: &str) -> PathBuf {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    data_dir
        .join(SCRATCH_DIR)
        .join(format!("session-{ts}-{kind}.db"))
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct StoragePayload {
    #[serde(flatten)]
    pub status: StorageStatus,
    /// Whether a database is attached to the current capture.
    pub active: bool,
}

pub fn emit_status(app: &AppHandle, pipeline: &Pipeline) {
    let payload = match pipeline.storage_status() {
        Some(status) => StoragePayload {
            status,
            active: true,
        },
        None => StoragePayload {
            status: StorageStatus::default(),
            active: false,
        },
    };
    let _ = app.emit("capture://storage", payload);
}

/// Starts persisting the next capture. Persistence is best effort: if it can't start, the capture
/// proceeds without it and the UI is told why.
pub fn attach(app: &AppHandle, state: &CaptureState, live: bool, source: &str) {
    if !state.persist.load(std::sync::atomic::Ordering::SeqCst) {
        return;
    }
    let Some(dir) = state.data_dir.lock_recover().clone() else {
        return;
    };
    clean_scratch(&dir);
    let path = new_session_path(&dir, if live { "live" } else { "file" });
    let config = if live {
        StorageConfig::live()
    } else {
        StorageConfig::import()
    };
    match state.pipeline.attach_storage(&path, config, source) {
        Ok(()) => {
            *state.session_db.lock_recover() = Some(path);
            emit_status(app, &state.pipeline);
        }
        Err(e) => {
            let _ = app.emit(
                "capture://storage",
                StoragePayload {
                    status: StorageStatus {
                        error: Some(e.to_string()),
                        ..Default::default()
                    },
                    active: false,
                },
            );
        }
    }
}

/// Flushes and closes the session database and reports the final state.
pub fn detach(app: &AppHandle, state: &CaptureState) {
    if let Some(result) = state.pipeline.detach_storage() {
        let payload = match result {
            Ok(status) => StoragePayload {
                status,
                active: false,
            },
            Err(e) => StoragePayload {
                status: StorageStatus {
                    error: Some(e.to_string()),
                    ..Default::default()
                },
                active: false,
            },
        };
        let _ = app.emit("capture://storage", payload);
    }
}

fn session_db(state: &CaptureState) -> Result<Database, CaptureError> {
    let path =
        state.session_db.lock_recover().clone().ok_or_else(|| {
            CaptureError::Storage("there is no stored capture to search yet".into())
        })?;
    Database::open(&path)
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PacketPage {
    packets: Vec<crate::protocols::PacketSummary>,
    /// Matching rows overall (ignores paging).
    total: u64,
}

/// Searches the full stored capture by indexed fields, independent of what the UI list holds.
#[tauri::command]
pub fn query_stored_packets(
    state: State<'_, CaptureState>,
    query: PacketQuery,
) -> Result<PacketPage, IpcError> {
    let db = session_db(&state)?;
    let packets = query_packets(&db, &query)?;
    let total = count_packets(&db, &query)?;
    Ok(PacketPage { packets, total })
}

#[tauri::command]
pub fn set_persistence(state: State<'_, CaptureState>, enabled: bool) {
    state
        .persist
        .store(enabled, std::sync::atomic::Ordering::SeqCst);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scratch_cleanup_removes_only_session_files() {
        let dir = tempfile::tempdir().unwrap();
        let scratch = dir.path().join(SCRATCH_DIR);
        fs::create_dir_all(&scratch).unwrap();
        for f in [
            "session-1-live.db",
            "session-1-live.db-wal",
            "session-2-file.db-shm",
            "keep.txt",
        ] {
            fs::write(scratch.join(f), b"x").unwrap();
        }
        clean_scratch(dir.path());
        let left: Vec<_> = fs::read_dir(&scratch)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(left, vec!["keep.txt"]);
        clean_scratch(&dir.path().join("does-not-exist")); // no panic
    }

    #[test]
    fn session_paths_are_unique_and_inside_scratch() {
        let dir = Path::new("/data");
        let a = new_session_path(dir, "live");
        assert!(a.starts_with("/data/scratch") && a.to_string_lossy().ends_with("-live.db"));
        std::thread::sleep(std::time::Duration::from_millis(2));
        assert_ne!(a, new_session_path(dir, "live"));
    }
}
