pub mod analytics;
pub mod capture;
pub mod commands;
pub mod flows;
pub mod pipeline;
pub mod process;
pub mod protocols;
pub mod security;
pub mod storage;

pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .manage(commands::capture::CaptureState::default())
        .setup(|app| {
            use tauri::Manager;
            if let Ok(dir) = app.path().app_data_dir() {
                commands::storage::clean_scratch(&dir);
                let state = app.state::<commands::capture::CaptureState>();
                *state.data_dir.lock().unwrap() = Some(dir);
            }
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::app_info,
            commands::capture::list_capture_interfaces,
            commands::capture::capture_start,
            commands::capture::capture_pause,
            commands::capture::capture_resume,
            commands::capture::capture_stop,
            commands::capture::get_packet_bytes,
            commands::capture::clear_capture,
            commands::capture::get_packet_detail,
            commands::capture::get_flows,
            commands::capture::get_dns,
            commands::capture::get_events,
            commands::capture::get_analytics,
            commands::files::open_capture,
            commands::files::cancel_open,
            commands::files::save_capture,
            commands::storage::query_stored_packets,
            commands::storage::set_persistence,
        ])
        .run(tauri::generate_context!())
        .expect("error while running ButurePacket");
}
