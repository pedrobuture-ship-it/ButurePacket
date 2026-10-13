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
        ])
        .run(tauri::generate_context!())
        .expect("error while running ButurePacket");
}
