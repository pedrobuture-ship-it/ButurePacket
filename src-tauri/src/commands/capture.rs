use std::sync::{Arc, Mutex};

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

#[derive(Default)]
pub struct CaptureState {
    session: Mutex<Option<CaptureSession>>,
    pub pipeline: Arc<Pipeline>,
}

#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
struct StatePayload {
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
}

impl CaptureSink for TauriSink {
    fn on_batch(&self, packets: Vec<RawPacket>) {
        if packets.is_empty() {
            return;
        }
        let out = self.pipeline.process(packets);
        let _ = self.app.emit("capture://packets", out.packets);
        if !out.flows.is_empty() {
            let _ = self.app.emit("capture://flows", out.flows);
        }
        if !out.dns.is_empty() || out.dns_stats.is_some() {
            let _ = self.app.emit(
                "capture://dns",
                DnsPayload {
                    transactions: out.dns,
                    stats: out.dns_stats,
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
    state.pipeline.clear();
    let sink = TauriSink {
        app,
        pipeline: state.pipeline.clone(),
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

/// Raw bytes of one packet, fetched only when the UI asks (inspector / hex view).
#[tauri::command]
pub fn get_packet_bytes(state: State<'_, CaptureState>, id: u64) -> Result<Vec<u8>, IpcError> {
    let store = state.pipeline.store.lock().unwrap();
    store
        .get(id)
        .map(|p| p.data.clone())
        .ok_or_else(|| IpcError {
            kind: "packetNotFound".into(),
            message: format!("Packet #{id} is no longer available."),
        })
}

#[tauri::command]
pub fn clear_capture(state: State<'_, CaptureState>) {
    state.pipeline.clear();
}

/// Layered, byte-mapped decode of one packet for the inspector.
#[tauri::command]
pub fn get_packet_detail(
    state: State<'_, CaptureState>,
    id: u64,
) -> Result<PacketDetail, IpcError> {
    let store = state.pipeline.store.lock().unwrap();
    store.get(id).map(build_detail).ok_or_else(|| IpcError {
        kind: "packetNotFound".into(),
        message: format!("Packet #{id} is no longer available."),
    })
}

#[tauri::command]
pub fn get_flows(state: State<'_, CaptureState>) -> Vec<FlowView> {
    state.pipeline.flows.lock().unwrap().snapshot()
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DnsSnapshot {
    transactions: Vec<DnsTransactionView>,
    stats: DnsStats,
}

#[tauri::command]
pub fn get_dns(state: State<'_, CaptureState>) -> DnsSnapshot {
    let dns = state.pipeline.dns.lock().unwrap();
    DnsSnapshot {
        transactions: dns.snapshot(),
        stats: dns.stats(),
    }
}
