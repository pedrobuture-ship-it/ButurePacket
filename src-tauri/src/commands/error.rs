use serde::Serialize;

use crate::capture::CaptureError;

/// Error shape sent over IPC: stable `kind` for the UI, human `message` for the user.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct IpcError {
    pub kind: String,
    pub message: String,
    /// What the user can do about it, when there is something to do.
    pub hint: Option<String>,
}

impl IpcError {
    /// Prefixes the message with what was being attempted ("Unable to start capture on eth0.").
    pub fn during(mut self, what: impl AsRef<str>) -> Self {
        self.message = format!("{} {}", what.as_ref(), self.message);
        self
    }
}

/// Messages shown to people read as sentences: capitalised, one full stop at the end.
fn sentence(text: &str) -> String {
    let t = text.trim().trim_end_matches('.');
    let mut chars = t.chars();
    match chars.next() {
        Some(first) => format!("{}{}.", first.to_uppercase(), chars.as_str()),
        None => String::new(),
    }
}

fn hint_for(e: &CaptureError) -> Option<&'static str> {
    Some(match e {
        CaptureError::PermissionDenied => {
            "Open the Capture screen to see how to grant permission. Opening PCAP files works without it."
        }
        CaptureError::InterfaceNotFound(_) => {
            "Choose another interface from the toolbar; it may have been unplugged or renamed."
        }
        CaptureError::InvalidFile(_) => {
            "Check that the file is a PCAP or PCAPNG capture and is not damaged."
        }
        CaptureError::Io(_) => {
            "Check that the file or folder exists and that you have permission to use it."
        }
        CaptureError::Storage(_) => {
            "Free some disk space, or turn off storing captures to disk in Settings."
        }
        CaptureError::Busy(_) => "Stop the running capture or wait for the open file to finish.",
        _ => return None,
    })
}

impl From<CaptureError> for IpcError {
    fn from(e: CaptureError) -> Self {
        IpcError {
            kind: e.kind().into(),
            message: sentence(&e.to_string()),
            hint: hint_for(&e).map(str::to_string),
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
        assert!(
            e.hint
                .as_deref()
                .is_some_and(|h| h.contains("Capture screen"))
        );
    }

    #[test]
    fn sentences_are_normalised() {
        assert_eq!(sentence("the file is empty"), "The file is empty.");
        assert_eq!(sentence("Already fine."), "Already fine.");
        assert_eq!(sentence("  spaced.. "), "Spaced.");
        assert_eq!(sentence(""), "");
    }

    #[test]
    fn context_is_prepended_without_changing_the_kind() {
        let e = IpcError::from(CaptureError::PermissionDenied)
            .during("Unable to start capture on eth0.");
        assert_eq!(e.kind, "permissionDenied");
        assert_eq!(
            e.message,
            "Unable to start capture on eth0. Packet capture permission is not available for this interface."
        );
    }

    #[test]
    fn every_user_facing_error_reads_as_a_sentence_and_never_leaks_raw_codes() {
        let all = [
            CaptureError::PermissionDenied,
            CaptureError::InterfaceNotFound("eth9".into()),
            CaptureError::AlreadyRunning,
            CaptureError::NotRunning,
            CaptureError::Backend("The interface is down. Bring it up and try again.".into()),
            CaptureError::InvalidFile("bad magic".into()),
            CaptureError::Io("'x' does not exist.".into()),
            CaptureError::Cancelled,
            CaptureError::Busy("Stop the capture first.".into()),
            CaptureError::Storage("disk full".into()),
        ];
        for e in all {
            let ipc = IpcError::from(e);
            assert!(ipc.message.ends_with('.'), "{}", ipc.message);
            assert!(
                ipc.message.chars().next().unwrap().is_uppercase(),
                "{}",
                ipc.message
            );
            assert!(!ipc.message.contains("Error -"), "{}", ipc.message);
            assert!(!ipc.kind.is_empty());
        }
    }
}
