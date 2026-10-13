//! Typed IPC surface: every `#[tauri::command]` lives here.

use serde::Serialize;

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AppInfo {
    pub name: &'static str,
    pub version: &'static str,
    pub platform: &'static str,
}

#[tauri::command]
pub fn app_info() -> AppInfo {
    AppInfo {
        name: "ButurePacket",
        version: env!("CARGO_PKG_VERSION"),
        platform: std::env::consts::OS,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn app_info_reports_crate_version() {
        let info = app_info();
        assert_eq!(info.name, "ButurePacket");
        assert_eq!(info.version, env!("CARGO_PKG_VERSION"));
    }
}
