use thiserror::Error;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum CaptureError {
    #[error("Packet capture permission is not available for this interface.")]
    PermissionDenied,
    #[error("Capture interface '{0}' was not found.")]
    InterfaceNotFound(String),
    #[error("A capture is already running.")]
    AlreadyRunning,
    #[error("No capture is running.")]
    NotRunning,
    #[error("Capture backend error: {0}")]
    Backend(String),
    /// Finite sources (tests, offline files) report their end this way. Not a failure.
    #[error("End of packet stream.")]
    EndOfStream,
}

impl From<pcap::Error> for CaptureError {
    fn from(e: pcap::Error) -> Self {
        let text = e.to_string();
        let lower = text.to_lowercase();
        if lower.contains("permission denied") || lower.contains("operation not permitted") {
            CaptureError::PermissionDenied
        } else if lower.contains("no such device") {
            CaptureError::InterfaceNotFound(text)
        } else {
            CaptureError::Backend(text)
        }
    }
}

impl CaptureError {
    /// Stable machine-readable identifier used by the frontend to pick UI.
    pub fn kind(&self) -> &'static str {
        match self {
            CaptureError::PermissionDenied => "permissionDenied",
            CaptureError::InterfaceNotFound(_) => "interfaceNotFound",
            CaptureError::AlreadyRunning => "alreadyRunning",
            CaptureError::NotRunning => "notRunning",
            CaptureError::Backend(_) => "backend",
            CaptureError::EndOfStream => "endOfStream",
        }
    }
}
