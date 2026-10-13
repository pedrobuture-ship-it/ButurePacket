use serde::Serialize;

use crate::capture::CaptureError;

/// Error shape sent over IPC: stable `kind` for the UI, human `message` for the user.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct IpcError {
    pub kind: String,
    pub message: String,
}

impl From<CaptureError> for IpcError {
    fn from(e: CaptureError) -> Self {
        IpcError {
            kind: e.kind().into(),
            message: e.to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capture_errors_keep_kind_and_message() {
        let e: IpcError = CaptureError::PermissionDenied.into();
        assert_eq!(e.kind, "permissionDenied");
        assert!(e.message.contains("permission"));
    }
}
