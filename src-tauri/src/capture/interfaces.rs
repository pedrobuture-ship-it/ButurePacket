use serde::Serialize;

use super::error::CaptureError;

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct InterfaceInfo {
    pub name: String,
    pub description: Option<String>,
    pub addresses: Vec<String>,
    pub loopback: bool,
    pub up: bool,
}

pub fn list_interfaces() -> Result<Vec<InterfaceInfo>, CaptureError> {
    let devices = pcap::Device::list()?;
    Ok(devices.into_iter().map(describe).collect())
}

fn describe(d: pcap::Device) -> InterfaceInfo {
    InterfaceInfo {
        loopback: d.flags.if_flags.contains(pcap::IfFlags::LOOPBACK),
        up: d.flags.if_flags.contains(pcap::IfFlags::UP),
        addresses: d.addresses.iter().map(|a| a.addr.to_string()).collect(),
        description: d.desc,
        name: d.name,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn listing_interfaces_does_not_panic() {
        // May legitimately be empty or fail in sandboxes; it must never panic.
        let _ = list_interfaces();
    }
}
