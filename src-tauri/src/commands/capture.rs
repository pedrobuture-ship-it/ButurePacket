use crate::util::LockRecover;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde::Serialize;
use tauri::{AppHandle, Emitter, State};

use super::error::IpcError;
use crate::analytics::dns::{DnsStats, DnsTransactionView};
use crate::capture::{
    CaptureError, CaptureSession, CaptureSink, InterfaceInfo, LiveSource, RawPacket, SessionConfig,
    SessionState, StatsSnapshot, list_interfaces,
};
use crate::flows::FlowView;
use crate::pipeline::Pipeline;
use crate::protocols::{PacketDetail, build_detail};

const ANALYTICS_INTERVAL: Duration = Duration::from_secs(1);

pub struct CaptureState {
    session: Mutex<Option<CaptureSession>>,
    pub pipeline: Arc<Pipeline>,
    /// A capture file is currently being opened.
    pub offline_running: Arc<AtomicBool>,
    pub offline_cancel: Mutex<Option<Arc<AtomicBool>>>,
    /// The data on screen came from a capture file (charts cover the whole file).
    pub offline_mode: AtomicBool,
    /// App data directory (scratch databases live under it).
    pub data_dir: Mutex<Option<std::path::PathBuf>>,
    /// Persist captures to the scratch database (on by default).
    pub persist: AtomicBool,
    /// Recently opened/saved files, shown on the Saved Captures screen.
    pub recent: Mutex<super::recent::RecentList>,
    /// Database of the capture on screen, opened read-only for searches.
    pub session_db: Mutex<Option<std::path::PathBuf>>,
}

impl Default for CaptureState {
    fn default() -> Self {
        Self {
            session: Mutex::default(),
            pipeline: Arc::default(),
            offline_running: Arc::default(),
            offline_cancel: Mutex::default(),
            offline_mode: AtomicBool::default(),
            data_dir: Mutex::default(),
            persist: AtomicBool::new(true),
            recent: Mutex::default(),
            session_db: Mutex::default(),
        }
    }
}

fn session_active(slot: &Option<CaptureSession>) -> bool {
    slot.as_ref()
        .is_some_and(|s| matches!(s.state(), SessionState::Running | SessionState::Paused))
}

/// Marks a file import as running and clears the mark again when dropped, however the import
/// ends (finished, failed, panicked, or never started).
pub struct ImportGuard(Arc<AtomicBool>);

impl Drop for ImportGuard {
    fn drop(&mut self) {
        self.0.store(false, std::sync::atomic::Ordering::SeqCst);
    }
}

impl CaptureState {
    /// A live capture is running or paused.
    pub fn live_active(&self) -> bool {
        session_active(&self.session.lock_recover())
    }

    /// Claims the right to import a file. Live capture and imports exclude each other: the check
    /// and the claim happen under the session lock, the same lock `capture_start` holds.
    pub fn begin_import(&self) -> Result<ImportGuard, CaptureError> {
        let slot = self.session.lock_recover();
        if session_active(&slot) {
            return Err(CaptureError::Busy(
                "Stop the current capture before opening a file.".into(),
            ));
        }
        self.offline_running
            .compare_exchange(
                false,
                true,
                std::sync::atomic::Ordering::SeqCst,
                std::sync::atomic::Ordering::SeqCst,
            )
            .map_err(|_| {
                CaptureError::Busy(
                    "Wait for the open file to finish, or cancel it, before opening another."
                        .into(),
                )
            })?;
        Ok(ImportGuard(self.offline_running.clone()))
    }

    /// Fails with `Busy` while a file is being imported.
    pub fn ensure_no_import(&self) -> Result<(), CaptureError> {
        if self
            .offline_running
            .load(std::sync::atomic::Ordering::SeqCst)
        {
            Err(CaptureError::Busy(
                "A file is being opened. Wait for it to finish or cancel it first.".into(),
            ))
        } else {
            Ok(())
        }
    }
}

pub fn state_payload(state: SessionState) -> StatePayload {
    StatePayload { state, error: None }
}

/// How often flow, DNS and event changes are pushed to the UI. Packet rows go out every batch.
pub const UPDATE_INTERVAL: Duration = Duration::from_millis(250);

/// Lets work happen at most once per interval.
pub struct Throttle(Mutex<Instant>);

impl Throttle {
    pub fn new() -> Self {
        Self(Mutex::new(Instant::now()))
    }

    pub fn due(&self, every: Duration) -> bool {
        let mut last = self.0.lock_recover();
        if last.elapsed() >= every {
            *last = Instant::now();
            true
        } else {
            false
        }
    }
}

impl Default for Throttle {
    fn default() -> Self {
        Self::new()
    }
}

/// Pushes one processed batch of packet rows to the frontend.
pub fn emit_processed(app: &AppHandle, out: crate::pipeline::Processed) {
    if !out.packets.is_empty() {
        let _ = app.emit("capture://packets", out.packets);
    }
}

/// Pushes accumulated flow, DNS and event changes to the frontend.
pub fn emit_updates(app: &AppHandle, up: crate::pipeline::Updates) {
    if !up.flows.is_empty() {
        let _ = app.emit("capture://flows", up.flows);
    }
    if !up.events.is_empty() {
        let _ = app.emit("capture://events", up.events);
    }
    if !up.dns.is_empty() || up.dns_stats.is_some() {
        let _ = app.emit(
            "capture://dns",
            DnsPayload {
                transactions: up.dns,
                stats: up.dns_stats,
            },
        );
    }
}

#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct StatePayload {
    state: SessionState,
    error: Option<IpcError>,
}

#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
struct DnsPayload {
    transactions: Vec<DnsTransactionView>,
    stats: Option<DnsStats>,
}

struct TauriSink {
    app: AppHandle,
    pipeline: Arc<Pipeline>,
    last_analytics: Mutex<Instant>,
    drain: Throttle,
}

impl CaptureSink for TauriSink {
    fn on_batch(&self, packets: Vec<RawPacket>) {
        if packets.is_empty() {
            return;
        }
        match self.pipeline.process_guarded(packets) {
            Ok(out) => {
                emit_processed(&self.app, out);
                if self.drain.due(UPDATE_INTERVAL) {
                    emit_updates(&self.app, self.pipeline.drain_updates());
                }
            }
            Err(msg) => {
                let _ = self.app.emit(
                    "capture://notice",
                    super::files::NoticePayload {
                        tone: "error",
                        text: format!(
                            "An internal error occurred while analysing a batch of packets; the batch was skipped. ({msg})"
                        ),
                    },
                );
            }
        }
    }

    fn on_stats(&self, stats: &StatsSnapshot) {
        let _ = self.app.emit("capture://stats", stats);
        if self.drain.due(UPDATE_INTERVAL) {
            emit_updates(&self.app, self.pipeline.drain_updates());
        }
        // Analytics are recomputed at most once a second: they scan the flow table.
        let mut last = self.last_analytics.lock_recover();
        if last.elapsed() >= ANALYTICS_INTERVAL {
            *last = Instant::now();
            let _ = self
                .app
                .emit("capture://analytics", self.pipeline.analytics(false));
            super::storage::emit_status(&self.app, &self.pipeline);
        }
    }

    fn on_state(&self, state: SessionState, error: Option<&CaptureError>) {
        if matches!(state, SessionState::Stopped | SessionState::Error) {
            // Whatever accumulated since the last push must reach the UI before it goes idle.
            emit_updates(&self.app, self.pipeline.drain_updates());
            // The capture is over, however it ended: flush and close its database.
            super::storage::detach_pipeline(&self.app, &self.pipeline);
        }
        let _ = self.app.emit(
            "capture://state",
            StatePayload {
                state,
                error: error.cloned().map(IpcError::from),
            },
        );
    }
}

#[tauri::command]
pub fn list_capture_interfaces() -> Result<Vec<InterfaceInfo>, IpcError> {
    list_interfaces().map_err(Into::into)
}

#[tauri::command]
pub fn capture_start(
    app: AppHandle,
    state: State<'_, CaptureState>,
    interface: String,
) -> Result<(), IpcError> {
    let mut slot = state.session.lock_recover();
    state.ensure_no_import()?;
    if let Some(existing) = slot.as_ref()
        && matches!(
            existing.state(),
            SessionState::Running | SessionState::Paused
        )
    {
        return Err(CaptureError::AlreadyRunning.into());
    }
    let source = LiveSource::open(&interface).map_err(|e| {
        IpcError::from(e).during(format!("Unable to start capture on {interface}."))
    })?;
    state.pipeline.clear();
    state
        .offline_mode
        .store(false, std::sync::atomic::Ordering::SeqCst);
    super::storage::attach(&app, &state, true, &interface);
    let sink = TauriSink {
        app,
        pipeline: state.pipeline.clone(),
        last_analytics: Mutex::new(Instant::now()),
        drain: Throttle::new(),
    };
    *slot = Some(CaptureSession::start(
        Box::new(source),
        Arc::new(sink),
        SessionConfig::default(),
    ));
    Ok(())
}

fn with_session<T>(
    state: &State<'_, CaptureState>,
    f: impl FnOnce(&mut CaptureSession) -> Result<T, CaptureError>,
) -> Result<T, IpcError> {
    let mut slot = state.session.lock_recover();
    match slot.as_mut() {
        Some(s) => f(s).map_err(Into::into),
        None => Err(CaptureError::NotRunning.into()),
    }
}

#[tauri::command]
pub fn capture_pause(state: State<'_, CaptureState>) -> Result<(), IpcError> {
    with_session(&state, |s| s.pause())
}

#[tauri::command]
pub fn capture_resume(state: State<'_, CaptureState>) -> Result<(), IpcError> {
    with_session(&state, |s| s.resume())
}

#[tauri::command]
pub fn capture_stop(app: AppHandle, state: State<'_, CaptureState>) -> Result<(), IpcError> {
    with_session(&state, |s| {
        s.stop();
        Ok(())
    })?;
    // Wait for the last batches to reach disk before the session is considered over.
    super::storage::detach(&app, &state);
    Ok(())
}

#[tauri::command]
pub fn clear_capture(app: AppHandle, state: State<'_, CaptureState>) -> Result<(), IpcError> {
    state.ensure_no_import()?;
    super::storage::detach(&app, &state);
    state.pipeline.clear();
    state
        .offline_mode
        .store(false, std::sync::atomic::Ordering::SeqCst);
    Ok(())
}

/// Layered, byte-mapped decode of one packet for the inspector.
#[tauri::command]
pub fn get_packet_detail(
    state: State<'_, CaptureState>,
    id: u64,
) -> Result<PacketDetail, IpcError> {
    let store = state.pipeline.store.lock_recover();
    store.get(id).map(build_detail).ok_or_else(|| IpcError {
        kind: "packetNotFound".into(),
        message: format!("Packet #{id} is no longer available."),
        hint: Some("The oldest packets are dropped from memory on very large captures.".into()),
    })
}

/// Whether live capture is permitted, with guidance when it is not. Read-only: nothing is elevated.
#[tauri::command]
pub async fn check_capture_permission()
-> Result<crate::capture::permission::PermissionReport, IpcError> {
    tauri::async_runtime::spawn_blocking(crate::capture::permission::check)
        .await
        .map_err(|e| CaptureError::Backend(e.to_string()).into())
}

/// One flow including its per-second traffic, for the flow inspector.
#[tauri::command]
pub fn get_flow(state: State<'_, CaptureState>, id: u64) -> Option<FlowView> {
    state.pipeline.flow_detail(id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capture::session::tests::{MockSource, TestSink};
    use std::collections::VecDeque;

    fn live_session() -> CaptureSession {
        let source = MockSource {
            packets: VecDeque::new(),
            finite: false,
            fail_with: None,
        };
        CaptureSession::start(
            Box::new(source),
            Arc::new(TestSink::default()),
            SessionConfig::default(),
        )
    }

    #[test]
    fn only_one_import_at_a_time_and_the_claim_is_released_on_drop() {
        let state = CaptureState::default();
        let first = state.begin_import().unwrap();
        assert!(matches!(state.begin_import(), Err(CaptureError::Busy(_))));
        assert!(matches!(
            state.ensure_no_import(),
            Err(CaptureError::Busy(_))
        ));
        drop(first);
        assert!(state.ensure_no_import().is_ok());
        assert!(state.begin_import().is_ok());
    }

    #[test]
    fn a_panicking_import_still_releases_the_claim() {
        let state = Arc::new(CaptureState::default());
        let guard = state.begin_import().unwrap();
        let t = std::thread::spawn(move || {
            let _guard = guard;
            panic!("worker blew up");
        });
        assert!(t.join().is_err());
        assert!(
            state.begin_import().is_ok(),
            "the app must not stay busy after a failed import"
        );
    }

    #[test]
    fn imports_and_live_capture_exclude_each_other() {
        let state = CaptureState::default();
        *state.session.lock_recover() = Some(live_session());
        assert!(state.live_active());
        assert!(
            matches!(state.begin_import(), Err(CaptureError::Busy(m)) if m.contains("Stop the current capture"))
        );
        // once the capture stops, importing is possible again
        state.session.lock_recover().as_mut().unwrap().stop();
        assert!(!state.live_active());
        let _import = state.begin_import().unwrap();
        assert!(state.ensure_no_import().is_err());
    }
}
