use crate::util::LockRecover;

pub mod analytics;
pub mod capture;
pub mod commands;
pub mod flows;
pub mod pipeline;
pub mod process;
pub mod protocols;
pub mod security;
pub mod storage;
#[cfg(any(test, feature = "testgen"))]
pub mod testgen;
pub mod util;

pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .manage(commands::capture::CaptureState::default())
        .setup(|app| {
            use tauri::Manager;
            if let Ok(dir) = app.path().app_data_dir() {
                commands::storage::clean_scratch(&dir);
                let state = app.state::<commands::capture::CaptureState>();
                *state.recent.lock_recover() =
                    commands::recent::RecentList::load(&dir.join("recent.json"));
                *state.data_dir.lock_recover() = Some(dir);
            }
            Ok(())
        })
        .on_window_event(|window, event| {
            use tauri::{DragDropEvent, Manager, WindowEvent};
            if let WindowEvent::DragDrop(DragDropEvent::Drop { paths, .. }) = event {
                commands::files::handle_drop(window.app_handle(), paths);
            }
        })
        .invoke_handler(tauri::generate_handler![
            commands::app_info,
            commands::capture::list_capture_interfaces,
            commands::capture::capture_start,
            commands::capture::capture_pause,
            commands::capture::capture_resume,
            commands::capture::capture_stop,
            commands::capture::clear_capture,
            commands::capture::get_packet_detail,
            commands::capture::get_flow,
            commands::capture::check_capture_permission,
            commands::files::pick_and_open_capture,
            commands::files::cancel_open,
            commands::files::pick_and_save_capture,
            commands::storage::query_stored_packets,
            commands::storage::set_persistence,
            commands::recent::list_recent_captures,
            commands::recent::open_recent_capture,
            commands::recent::forget_recent_capture,
        ])
        .run(tauri::generate_context!())
        .expect("error while running ButurePacket");
}
