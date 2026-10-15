//! Reports whether this process may capture packets, and explains how to fix it when it can't.
//! Nothing here ever elevates privileges, runs `sudo`, or executes the suggested commands.

use std::path::Path;

use serde::Serialize;

use super::interfaces::{InterfaceInfo, list_interfaces};

const CAP_NET_ADMIN_BIT: u32 = 12;
const CAP_NET_RAW_BIT: u32 = 13;
const MAX_PROBES: usize = 24;

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum PermissionState {
    /// Live capture works on the interfaces that matter.
    Available,
    /// Some interfaces can be captured, others cannot.
    Limited,
    /// Live capture is not permitted. Opening capture files still works.
    Unavailable,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct InterfaceProbe {
    pub name: String,
    pub description: Option<String>,
    pub openable: bool,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PermissionReport {
    pub state: PermissionState,
    pub platform: &'static str,
    pub running_as_root: bool,
    pub has_net_raw: Option<bool>,
    pub has_net_admin: Option<bool>,
    pub interfaces: Vec<InterfaceProbe>,
    pub executable: Option<String>,
    pub summary: String,
    /// Plain-language steps for the user.
    pub guidance: Vec<String>,
    /// Commands the user may choose to run themselves. B&M Packet never runs them.
    pub commands: Vec<String>,
}

/// Effective capability bitmask from the text of `/proc/<pid>/status`.
pub fn parse_cap_eff(status: &str) -> Option<u64> {
    let line = status.lines().find_map(|l| l.strip_prefix("CapEff:"))?;
    u64::from_str_radix(line.trim(), 16).ok()
}

/// Effective user id from the text of `/proc/<pid>/status`.
pub fn parse_euid(status: &str) -> Option<u32> {
    let line = status.lines().find_map(|l| l.strip_prefix("Uid:"))?;
    line.split_whitespace().nth(1)?.parse().ok()
}

/// Quotes a path for safe pasting into a POSIX shell.
pub fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// Interfaces that are not real network links and often refuse to open for unrelated reasons.
fn is_pseudo(name: &str) -> bool {
    matches!(name, "any" | "nflog" | "nfqueue")
        || name.starts_with("dbus")
        || name.starts_with("usbmon")
        || name.starts_with("bluetooth")
}

pub fn classify(probes: &[InterfaceProbe]) -> PermissionState {
    let real: Vec<&InterfaceProbe> = probes.iter().filter(|p| !is_pseudo(&p.name)).collect();
    let (ok, bad) = (
        real.iter().filter(|p| p.openable).count(),
        real.iter().filter(|p| !p.openable).count(),
    );
    match (ok, bad) {
        (0, _) => PermissionState::Unavailable,
        (_, 0) => PermissionState::Available,
        _ => PermissionState::Limited,
    }
}

fn probe(i: &InterfaceInfo) -> InterfaceProbe {
    // Non-promiscuous and immediately closed: checking must not change the interface.
    let result = pcap::Capture::from_device(i.name.as_str())
        .and_then(|c| c.promisc(false).snaplen(64).timeout(10).open());
    let (openable, error) = match result {
        Ok(_) => (true, None),
        Err(e) => (false, Some(super::error::CaptureError::from(e).to_string())),
    };
    InterfaceProbe {
        name: i.name.clone(),
        description: i.description.clone(),
        openable,
        error,
    }
}

pub fn guidance_for(state: PermissionState, exe: Option<&str>) -> (Vec<String>, Vec<String>) {
    if state == PermissionState::Available {
        return (
            vec!["Live capture is available. You can start capturing from the toolbar.".into()],
            vec![],
        );
    }
    let mut guidance = vec![
        "B&M Packet needs permission from the operating system to read packets from a network interface.".into(),
        "It never asks for your password and never runs sudo for you.".into(),
        "You can still open and analyse PCAP and PCAPNG files without any special permission.".into(),
    ];
    let mut commands = vec![];
    if cfg!(target_os = "linux") {
        guidance.push("On Linux, the usual fix is to grant the program the packet-capture capabilities once. Run this command yourself in a terminal:".into());
        let target = exe
            .map(shell_quote)
            .unwrap_or_else(|| "/path/to/buturepacket".into());
        commands.push(format!(
            "sudo setcap cap_net_raw,cap_net_admin=eip {target}"
        ));
        guidance.push("Then restart B&M Packet. Running the whole application as root is possible but not recommended.".into());
    } else {
        guidance.push("Grant packet-capture access to this application in your operating system, then restart it.".into());
    }
    (guidance, commands)
}

/// Probes the system. Safe to call repeatedly; opens (and closes) each interface once.
pub fn check() -> PermissionReport {
    let status = std::fs::read_to_string("/proc/self/status").ok();
    let caps = status.as_deref().and_then(parse_cap_eff);
    let root = status
        .as_deref()
        .and_then(parse_euid)
        .is_some_and(|u| u == 0);
    let exe = std::env::current_exe().ok().map(|p| display_path(&p));

    let listed = list_interfaces();
    let probes: Vec<InterfaceProbe> = match &listed {
        Ok(list) => list.iter().take(MAX_PROBES).map(probe).collect(),
        Err(_) => vec![],
    };
    let state = classify(&probes);
    let (guidance, commands) = guidance_for(state, exe.as_deref());
    let summary = match (state, &listed) {
        (_, Err(e)) => format!("The list of network interfaces could not be read: {e}"),
        (PermissionState::Available, _) => "Packet capture is available.".into(),
        (PermissionState::Limited, _) => {
            "Packet capture works on some interfaces but not others.".into()
        }
        (PermissionState::Unavailable, Ok(l)) if l.is_empty() => {
            "No network interfaces were found.".into()
        }
        (PermissionState::Unavailable, _) => "Packet capture permission is not available.".into(),
    };
    PermissionReport {
        state,
        platform: std::env::consts::OS,
        running_as_root: root,
        has_net_raw: caps.map(|c| c & (1 << CAP_NET_RAW_BIT) != 0),
        has_net_admin: caps.map(|c| c & (1 << CAP_NET_ADMIN_BIT) != 0),
        interfaces: probes,
        executable: exe,
        summary,
        guidance,
        commands,
    }
}

fn display_path(p: &Path) -> String {
    p.to_string_lossy().into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(name: &str, ok: bool) -> InterfaceProbe {
        InterfaceProbe {
            name: name.into(),
            description: None,
            openable: ok,
            error: (!ok).then(|| "denied".to_string()),
        }
    }

    #[test]
    fn parses_proc_status() {
        let s = "Name:\tbuturepacket\nUid:\t1000\t1001\t1000\t1000\nCapEff:\t0000000000003000\n";
        assert_eq!(parse_euid(s), Some(1001));
        let caps = parse_cap_eff(s).unwrap();
        assert_ne!(caps & (1 << CAP_NET_RAW_BIT), 0);
        assert_ne!(caps & (1 << CAP_NET_ADMIN_BIT), 0);
        assert_eq!(parse_cap_eff("CapEff:\t0000000000000000\n"), Some(0));
        assert_eq!(parse_cap_eff("nothing here"), None);
        assert_eq!(parse_cap_eff("CapEff:\tzzzz"), None);
        assert_eq!(parse_euid("Uid:\tx"), None);
    }

    #[test]
    fn classification() {
        assert_eq!(classify(&[]), PermissionState::Unavailable);
        assert_eq!(
            classify(&[p("eth0", true), p("lo", true)]),
            PermissionState::Available
        );
        assert_eq!(
            classify(&[p("eth0", false), p("lo", false)]),
            PermissionState::Unavailable
        );
        assert_eq!(
            classify(&[p("eth0", true), p("wlan0", false)]),
            PermissionState::Limited
        );
        // pseudo devices don't count either way
        assert_eq!(
            classify(&[
                p("eth0", true),
                p("any", false),
                p("nflog", false),
                p("dbus-system", false)
            ]),
            PermissionState::Available
        );
        assert_eq!(
            classify(&[p("any", true), p("eth0", false)]),
            PermissionState::Unavailable
        );
    }

    #[test]
    fn shell_quoting_neutralises_hostile_paths() {
        assert_eq!(shell_quote("/usr/bin/x"), "'/usr/bin/x'");
        assert_eq!(shell_quote("/tmp/it's"), "'/tmp/it'\\''s'");
        assert_eq!(shell_quote("/tmp/$(rm -rf ~)"), "'/tmp/$(rm -rf ~)'");
        assert_eq!(shell_quote("/tmp/a b;c"), "'/tmp/a b;c'");
    }

    #[test]
    fn guidance_never_automates_elevation() {
        let (g, c) = guidance_for(
            PermissionState::Unavailable,
            Some("/opt/my app/buturepacket"),
        );
        assert!(g.iter().any(|l| l.contains("never asks for your password")));
        if cfg!(target_os = "linux") {
            assert_eq!(
                c,
                vec![
                    "sudo setcap cap_net_raw,cap_net_admin=eip '/opt/my app/buturepacket'"
                        .to_string()
                ]
            );
        }
        let (g, c) = guidance_for(PermissionState::Available, None);
        assert!(c.is_empty() && g.len() == 1);
    }

    #[test]
    fn checking_never_panics_and_reports_consistently() {
        let r = check();
        assert!(!r.summary.is_empty());
        assert_eq!(r.state, classify(&r.interfaces));
        assert_eq!(r.commands.is_empty(), r.state == PermissionState::Available);
        assert!(r.interfaces.len() <= MAX_PROBES);
    }
}
