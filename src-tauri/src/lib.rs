pub mod analytics;
pub mod capture;
pub mod commands;
pub mod flows;
pub mod process;
pub mod protocols;
pub mod security;
pub mod storage;

pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .invoke_handler(tauri::generate_handler![commands::app_info])
        .run(tauri::generate_context!())
        .expect("error while running ButurePacket");
}
