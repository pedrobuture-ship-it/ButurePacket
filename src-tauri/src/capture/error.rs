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
    #[error("{0}")]
    Backend(String),
    #[error("This file is not a readable capture: {0}")]
    InvalidFile(String),
    #[error("File error: {0}")]
    Io(String),
    #[error("The operation was cancelled.")]
    Cancelled,
    #[error("{0}")]
    Busy(String),
    #[error("Could not use the capture database: {0}")]
    Storage(String),
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
        } else if lower.contains("not up") || lower.contains("network is down") {
            CaptureError::Backend("The interface is down. Bring it up and try again.".into())
        } else if lower.contains("resource busy") {
            CaptureError::Backend("The interface is busy, possibly used by another capture.".into())
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
            CaptureError::InvalidFile(_) => "invalidCaptureFile",
            CaptureError::Io(_) => "io",
            CaptureError::Cancelled => "cancelled",
            CaptureError::Busy(_) => "busy",
            CaptureError::Storage(_) => "storage",
            CaptureError::EndOfStream => "endOfStream",
        }
    }
}

impl From<std::io::Error> for CaptureError {
    fn from(e: std::io::Error) -> Self {
        CaptureError::Io(e.to_string())
    }
}
