use std::sync::{Arc, Mutex};

use serde::Serialize;
use tauri::{AppHandle, Emitter, State};

use super::error::IpcError;
use crate::capture::{
    CaptureError, CaptureSession, CaptureSink, InterfaceInfo, LiveSource, RawPacket, SessionConfig,
    SessionState, StatsSnapshot, list_interfaces,
};

#[derive(Default)]
pub struct CaptureState {
    session: Mutex<Option<CaptureSession>>,
}

#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
struct StatePayload {
    state: SessionState,
    error: Option<IpcError>,
}

#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
struct BatchPayload {
    count: usize,
    first_id: u64,
    last_id: u64,
}

struct TauriSink {
    app: AppHandle,
}

impl CaptureSink for TauriSink {
    fn on_batch(&self, packets: Vec<RawPacket>) {
        if let (Some(first), Some(last)) = (packets.first(), packets.last()) {
            let _ = self.app.emit(
                "capture://batch",
                BatchPayload {
                    count: packets.len(),
                    first_id: first.id,
                    last_id: last.id,
                },
            );
        }
    }

    fn on_stats(&self, stats: &StatsSnapshot) {
        let _ = self.app.emit("capture://stats", stats);
    }

    fn on_state(&self, state: SessionState, error: Option<&CaptureError>) {
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
    let mut slot = state.session.lock().unwrap();
    if let Some(existing) = slot.as_ref()
        && matches!(
            existing.state(),
            SessionState::Running | SessionState::Paused
        )
    {
        return Err(CaptureError::AlreadyRunning.into());
    }
    let source = LiveSource::open(&interface)?;
    *slot = Some(CaptureSession::start(
        Box::new(source),
        Arc::new(TauriSink { app }),
        SessionConfig::default(),
    ));
    Ok(())
}

fn with_session<T>(
    state: &State<'_, CaptureState>,
    f: impl FnOnce(&mut CaptureSession) -> Result<T, CaptureError>,
) -> Result<T, IpcError> {
    let mut slot = state.session.lock().unwrap();
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
pub fn capture_stop(state: State<'_, CaptureState>) -> Result<(), IpcError> {
    with_session(&state, |s| {
        s.stop();
        Ok(())
    })
}
