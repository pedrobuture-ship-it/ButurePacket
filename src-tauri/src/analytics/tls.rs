//! Per-flow TLS metadata. Reassembles just enough of each TCP direction (in-order bytes only,
//! at most 32 KiB) to read the handshake, and never decrypts anything.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::protocols::tls::{self, CertMeta, TlsParse};

const MAX_STREAM_BYTES: usize = 32 * 1024;
const MAX_TRACKED_FLOWS: usize = 100_000;

/// What is known about a flow's TLS session. Absent fields mean "not observable", never "guessed".
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct TlsInfo {
    pub version: Option<String>,
    pub sni: Option<String>,
    pub alpn_offered: Vec<String>,
    pub alpn_selected: Option<String>,
    pub cipher_suite: Option<String>,
    pub certificate: Option<CertMeta>,
    pub client_hello_at: Option<i64>,
    pub server_hello_at: Option<i64>,
    /// TLS 1.3: the certificate and ALPN choice travel encrypted, so they cannot be shown.
    pub handshake_encrypted: bool,
}

#[derive(Debug, Default)]
struct Stream {
    next_seq: Option<u32>,
    data: Vec<u8>,
    closed: bool,
}

impl Stream {
    /// Appends in-order bytes; anything else (gap, non-TLS start) ends collection for this direction.
    fn push(&mut self, seq: u32, payload: &[u8]) -> bool {
        if self.closed || payload.is_empty() {
            return false;
        }
        let fresh = match self.next_seq {
            None => {
                if !tls::looks_like_tls(payload) {
                    self.closed = true;
                    return false;
                }
                payload
            }
            Some(next) if seq == next => payload,
            Some(next) if (seq.wrapping_sub(next) as i32) < 0 => {
                let overlap = next.wrapping_sub(seq) as usize; // retransmission: keep only the new tail
                match payload.get(overlap..) {
                    Some(tail) if !tail.is_empty() => tail,
                    _ => return false,
                }
            }
            Some(_) => {
                self.closed = true; // gap: we'd be guessing
                return false;
            }
        };
        let room = MAX_STREAM_BYTES.saturating_sub(self.data.len());
        let take = &fresh[..fresh.len().min(room)];
        self.data.extend_from_slice(take);
        self.next_seq = Some(
            seq.wrapping_add(payload.len() as u32)
                .max(self.next_seq.unwrap_or(0))
                .min(seq.wrapping_add(payload.len() as u32)),
        );
        if take.len() < fresh.len() || self.data.len() >= MAX_STREAM_BYTES {
            self.closed = true;
        }
        true
    }
}

#[derive(Debug, Default)]
struct FlowTls {
    streams: [Stream; 2],
    info: TlsInfo,
}

#[derive(Debug, Default)]
pub struct TlsTracker {
    flows: HashMap<u64, FlowTls>,
}

impl TlsTracker {
    /// Feeds one TCP payload. Returns the updated info when it changed.
    pub fn observe(
        &mut self,
        flow_id: u64,
        a_to_b: bool,
        ts: i64,
        seq: u32,
        payload: &[u8],
    ) -> Option<TlsInfo> {
        if payload.is_empty() {
            return None;
        }
        if !self.flows.contains_key(&flow_id) {
            // Only start tracking flows that open with something TLS-shaped.
            if !tls::looks_like_tls(payload) || self.flows.len() >= MAX_TRACKED_FLOWS {
                return None;
            }
            self.flows.insert(flow_id, FlowTls::default());
        }
        let state = self.flows.get_mut(&flow_id)?;
        let stream = &mut state.streams[usize::from(!a_to_b)];
        if !stream.push(seq, payload) {
            return None;
        }
        let parsed = tls::parse(&stream.data);
        if parsed.client_hello.is_some()
            || parsed.saw_non_handshake
            || (parsed.server_hello.is_some() && parsed.certificate.is_some())
        {
            stream.closed = true;
            // Keep the (now useless) buffer from lingering.
            stream.data = Vec::new();
        }
        let before = state.info.clone();
        merge(&mut state.info, &parsed, ts);
        (state.info != before).then(|| state.info.clone())
    }

    pub fn info(&self, flow_id: u64) -> Option<&TlsInfo> {
        self.flows
            .get(&flow_id)
            .map(|f| &f.info)
            .filter(|i| **i != TlsInfo::default())
    }

    pub fn clear(&mut self) {
        self.flows.clear();
    }
}

fn merge(info: &mut TlsInfo, p: &TlsParse, ts: i64) {
    if let Some(h) = &p.client_hello {
        info.sni
            .get_or_insert_with(|| h.sni.clone().unwrap_or_default());
        if info.sni.as_deref() == Some("") {
            info.sni = None;
        }
        if info.alpn_offered.is_empty() {
            info.alpn_offered = h.alpn.clone();
        }
        info.client_hello_at.get_or_insert(ts);
    }
    if let Some(s) = &p.server_hello {
        let version = s.selected_version.unwrap_or(s.legacy_version);
        info.version = Some(tls::version_name(version));
        info.cipher_suite = Some(tls::cipher_suite_name(s.cipher_suite));
        info.alpn_selected = s.alpn.clone();
        info.handshake_encrypted = version == 0x0304;
        info.server_hello_at.get_or_insert(ts);
    }
    if let Some(c) = &p.certificate {
        info.certificate = Some(c.clone());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocols::tls::tests::{certificate_record, client_hello, record, server_hello};

    const T0: i64 = 1_000_000;

    #[test]
    fn extracts_sni_and_alpn_offer_from_a_client_hello() {
        let mut t = TlsTracker::default();
        let hello = client_hello("github.com", &["h2", "http/1.1"]);
        let info = t.observe(1, true, T0, 1000, &hello).unwrap();
        assert_eq!(info.sni.as_deref(), Some("github.com"));
        assert_eq!(info.alpn_offered, vec!["h2", "http/1.1"]);
        assert_eq!(info.client_hello_at, Some(T0));
        assert_eq!(info.version, None); // not negotiated yet: don't invent it
    }

    #[test]
    fn tls13_server_hello_gives_version_and_cipher_but_not_certificate() {
        let mut t = TlsTracker::default();
        t.observe(1, true, T0, 1, &client_hello("github.com", &["h2"]));
        let mut sh = server_hello(true, 0x1301, None);
        sh.extend(record(20, &[1]));
        sh.extend(record(23, &[0; 64]));
        let info = t.observe(1, false, T0 + 30_000, 500, &sh).unwrap();
        assert_eq!(info.version.as_deref(), Some("TLS 1.3"));
        assert_eq!(info.cipher_suite.as_deref(), Some("TLS_AES_128_GCM_SHA256"));
        assert!(info.handshake_encrypted && info.certificate.is_none());
        assert_eq!(info.alpn_selected, None);
        assert_eq!(info.server_hello_at, Some(T0 + 30_000));
        assert_eq!(info.sni.as_deref(), Some("github.com"));
    }

    #[test]
    fn tls12_certificate_split_across_segments_is_reassembled() {
        let mut t = TlsTracker::default();
        let mut flight = server_hello(false, 0xc02f, Some("h2"));
        flight.extend(certificate_record(
            "example.org",
            "Test CA",
            &["example.org", "*.example.org"],
        ));
        let (a, b) = flight.split_at(flight.len() / 2);
        let first = t.observe(7, false, T0, 5000, a).unwrap();
        assert_eq!(first.version.as_deref(), Some("TLS 1.2")); // hello already readable
        assert!(first.certificate.is_none());
        let second = t
            .observe(7, false, T0 + 1, 5000 + a.len() as u32, b)
            .unwrap();
        let cert = second.certificate.unwrap();
        assert_eq!(cert.subject_cn.as_deref(), Some("example.org"));
        assert_eq!(cert.dns_names, vec!["example.org", "*.example.org"]);
        assert_eq!(second.alpn_selected.as_deref(), Some("h2"));
        assert!(!second.handshake_encrypted);
    }

    #[test]
    fn client_hello_split_in_two_segments() {
        let mut t = TlsTracker::default();
        let hello = client_hello("split.example", &["h2"]);
        let (a, b) = hello.split_at(30);
        assert!(t.observe(1, true, T0, 100, a).is_none());
        let info = t.observe(1, true, T0 + 5, 130, b).unwrap();
        assert_eq!(info.sni.as_deref(), Some("split.example"));
    }

    #[test]
    fn retransmissions_do_not_corrupt_reassembly() {
        let mut t = TlsTracker::default();
        let hello = client_hello("retx.example", &[]);
        let (a, b) = hello.split_at(30);
        t.observe(1, true, T0, 100, a);
        t.observe(1, true, T0 + 1, 100, a); // exact retransmission
        t.observe(1, true, T0 + 2, 90, &[&hello[..0], a].concat()); // stale seq, fully old
        let info = t.observe(1, true, T0 + 3, 130, b).unwrap();
        assert_eq!(info.sni.as_deref(), Some("retx.example"));
    }

    #[test]
    fn gaps_stop_collection_instead_of_guessing() {
        let mut t = TlsTracker::default();
        let hello = client_hello("gap.example", &[]);
        let (a, b) = hello.split_at(30);
        t.observe(1, true, T0, 100, a);
        assert!(t.observe(1, true, T0 + 1, 9999, b).is_none());
        assert!(t.info(1).is_none());
    }

    #[test]
    fn non_tls_flows_are_ignored() {
        let mut t = TlsTracker::default();
        assert!(
            t.observe(1, true, T0, 1, b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
                .is_none()
        );
        assert!(t.info(1).is_none());
        assert!(t.observe(2, true, T0, 1, &[]).is_none());
    }

    #[test]
    fn sequence_numbers_wrap() {
        let mut t = TlsTracker::default();
        let hello = client_hello("wrap.example", &[]);
        let (a, b) = hello.split_at(30);
        let start = u32::MAX - 10;
        t.observe(1, true, T0, start, a);
        let info = t
            .observe(1, true, T0 + 1, start.wrapping_add(30), b)
            .unwrap();
        assert_eq!(info.sni.as_deref(), Some("wrap.example"));
    }

    #[test]
    fn unchanged_info_is_not_reported_twice() {
        let mut t = TlsTracker::default();
        let hello = client_hello("a.example", &[]);
        assert!(t.observe(1, true, T0, 1, &hello).is_some());
        assert!(t.observe(1, true, T0 + 1, 1, &hello).is_none());
    }
}
