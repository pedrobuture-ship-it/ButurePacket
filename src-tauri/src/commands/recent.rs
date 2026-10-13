//! Recently opened or saved capture files, remembered by the backend so the web view only ever
//! refers to them by an opaque id (it never supplies a file path).

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Manager, State};

use super::capture::CaptureState;
use super::error::IpcError;
use crate::capture::CaptureError;
use crate::util::LockRecover;

const MAX_RECENT: usize = 20;
const FILE_NAME: &str = "recent.json";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RecentFile {
    pub id: u64,
    pub path: PathBuf,
    /// Unix milliseconds of the last time it was opened or saved.
    pub used_at: i64,
}

/// What the web view sees: no full path, just enough to recognise the file.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RecentView {
    pub id: u64,
    pub name: String,
    pub folder: String,
    pub used_at: i64,
    pub size: Option<u64>,
    /// The file is still where it was.
    pub exists: bool,
}

#[derive(Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct RecentList {
    next_id: u64,
    items: Vec<RecentFile>,
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

impl RecentList {
    pub fn load(path: &Path) -> Self {
        fs::read_to_string(path)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default()
    }

    pub fn save(&self, path: &Path) -> Result<(), CaptureError> {
        if let Some(dir) = path.parent() {
            fs::create_dir_all(dir)?;
        }
        let tmp = path.with_extension("json.tmp");
        fs::write(
            &tmp,
            serde_json::to_vec_pretty(self).map_err(|e| CaptureError::Io(e.to_string()))?,
        )?;
        fs::rename(&tmp, path)?;
        Ok(())
    }

    /// Records a use of `file` (moving it to the top, de-duplicated by path).
    pub fn touch(&mut self, file: &Path) {
        let canonical = fs::canonicalize(file).unwrap_or_else(|_| file.to_path_buf());
        let id = self
            .items
            .iter()
            .find(|r| r.path == canonical)
            .map(|r| r.id)
            .unwrap_or_else(|| {
                self.next_id += 1;
                self.next_id
            });
        self.items.retain(|r| r.path != canonical);
        self.items.insert(
            0,
            RecentFile {
                id,
                path: canonical,
                used_at: now_ms(),
            },
        );
        self.items.truncate(MAX_RECENT);
    }

    pub fn path_of(&self, id: u64) -> Option<PathBuf> {
        self.items
            .iter()
            .find(|r| r.id == id)
            .map(|r| r.path.clone())
    }

    pub fn forget(&mut self, id: u64) -> bool {
        let before = self.items.len();
        self.items.retain(|r| r.id != id);
        self.items.len() != before
    }

    pub fn clear(&mut self) {
        self.items.clear();
    }

    pub fn views(&self) -> Vec<RecentView> {
        self.items
            .iter()
            .map(|r| {
                let meta = fs::metadata(&r.path).ok();
                RecentView {
                    id: r.id,
                    name: r
                        .path
                        .file_name()
                        .map(|n| n.to_string_lossy().into_owned())
                        .unwrap_or_default(),
                    folder: r
                        .path
                        .parent()
                        .map(|p| p.to_string_lossy().into_owned())
                        .unwrap_or_default(),
                    used_at: r.used_at,
                    size: meta.as_ref().filter(|m| m.is_file()).map(|m| m.len()),
                    exists: meta.is_some_and(|m| m.is_file()),
                }
            })
            .collect()
    }
}

fn store_path(app: &AppHandle) -> Option<PathBuf> {
    app.path().app_data_dir().ok().map(|d| d.join(FILE_NAME))
}

/// Remembers `file` as recently used. Best effort: failure to persist is never an error for the user.
pub fn remember(app: &AppHandle, file: &Path) {
    let state = app.state::<CaptureState>();
    let mut list = state.recent.lock_recover();
    list.touch(file);
    if let Some(p) = store_path(app) {
        let _ = list.save(&p);
    }
}

#[tauri::command]
pub fn list_recent_captures(state: State<'_, CaptureState>) -> Vec<RecentView> {
    state.recent.lock_recover().views()
}

#[tauri::command]
pub fn forget_recent_capture(app: AppHandle, state: State<'_, CaptureState>, id: Option<u64>) {
    let mut list = state.recent.lock_recover();
    match id {
        Some(id) => {
            list.forget(id);
        }
        None => list.clear(),
    }
    if let Some(p) = store_path(&app) {
        let _ = list.save(&p);
    }
}

#[tauri::command]
pub fn open_recent_capture(
    app: AppHandle,
    state: State<'_, CaptureState>,
    id: u64,
) -> Result<(), IpcError> {
    let path =
        state.recent.lock_recover().path_of(id).ok_or_else(|| {
            CaptureError::Io("That capture is no longer in the recent list.".into())
        })?;
    super::files::start_open(app, &state, path).map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make(dir: &Path, name: &str) -> PathBuf {
        let p = dir.join(name);
        fs::write(&p, b"x").unwrap();
        p
    }

    #[test]
    fn touching_moves_to_top_and_deduplicates_by_path() {
        let dir = tempfile::tempdir().unwrap();
        let (a, b) = (make(dir.path(), "a.pcap"), make(dir.path(), "b.pcap"));
        let mut l = RecentList::default();
        l.touch(&a);
        l.touch(&b);
        l.touch(&a);
        let v = l.views();
        assert_eq!(
            v.iter().map(|r| r.name.as_str()).collect::<Vec<_>>(),
            vec!["a.pcap", "b.pcap"]
        );
        let id_a = v[0].id;
        l.touch(&a);
        assert_eq!(l.views()[0].id, id_a); // ids are stable
        assert!(l.views().iter().all(|r| r.exists && r.size == Some(1)));
    }

    #[test]
    fn list_is_bounded_and_ids_are_unique() {
        let dir = tempfile::tempdir().unwrap();
        let mut l = RecentList::default();
        for i in 0..(MAX_RECENT + 5) {
            l.touch(&make(dir.path(), &format!("f{i}.pcap")));
        }
        let v = l.views();
        assert_eq!(v.len(), MAX_RECENT);
        let ids: std::collections::HashSet<_> = v.iter().map(|r| r.id).collect();
        assert_eq!(ids.len(), MAX_RECENT);
        assert_eq!(v[0].name, format!("f{}.pcap", MAX_RECENT + 4));
    }

    #[test]
    fn opening_is_by_id_only_and_missing_files_are_flagged() {
        let dir = tempfile::tempdir().unwrap();
        let a = make(dir.path(), "a.pcap");
        let mut l = RecentList::default();
        l.touch(&a);
        let id = l.views()[0].id;
        assert_eq!(l.path_of(id).unwrap().file_name().unwrap(), "a.pcap");
        assert!(l.path_of(id + 100).is_none());
        fs::remove_file(&a).unwrap();
        let v = l.views();
        assert!(!v[0].exists);
        assert_eq!(v[0].size, None);
    }

    #[test]
    fn forgetting_and_clearing() {
        let dir = tempfile::tempdir().unwrap();
        let mut l = RecentList::default();
        l.touch(&make(dir.path(), "a.pcap"));
        l.touch(&make(dir.path(), "b.pcap"));
        let id = l.views()[0].id;
        assert!(l.forget(id));
        assert!(!l.forget(id));
        assert_eq!(l.views().len(), 1);
        l.clear();
        assert!(l.views().is_empty());
    }

    #[test]
    fn persists_atomically_and_survives_garbage() {
        let dir = tempfile::tempdir().unwrap();
        let store = dir.path().join("sub/recent.json");
        let mut l = RecentList::default();
        l.touch(&make(dir.path(), "a.pcap"));
        l.save(&store).unwrap();
        assert_eq!(RecentList::load(&store), l);
        assert!(!store.with_extension("json.tmp").exists());
        fs::write(&store, b"{ not json").unwrap();
        assert_eq!(RecentList::load(&store), RecentList::default());
        assert_eq!(
            RecentList::load(&dir.path().join("missing.json")),
            RecentList::default()
        );
    }
}
