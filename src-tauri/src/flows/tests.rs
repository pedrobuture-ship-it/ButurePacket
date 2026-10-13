use super::flow::TcpState;
use super::input::{FlowInput, TcpInfo};
use super::key::{Endpoint, Proto};
use super::{FlowEngine, FlowView};
use crate::capture::RawPacket;
use crate::protocols::tcp::{ACK, FIN, PSH, RST, SYN};
use crate::protocols::{dissect, summary::summarize};

const CLIENT: &str = "192.168.1.20";
const SERVER: &str = "140.82.121.4";
const SEC: i64 = 1_000_000;

fn ep(ip: &str, port: u16) -> Endpoint {
    Endpoint {
        ip: ip.parse().unwrap(),
        port,
    }
}

fn tcp(ts: i64, from_client: bool, flags: u16, seq: u32, ack: u32, len: u32) -> FlowInput {
    tcp_w(ts, from_client, flags, seq, ack, len, 64240)
}

fn tcp_w(
    ts: i64,
    from_client: bool,
    flags: u16,
    seq: u32,
    ack: u32,
    len: u32,
    window: u16,
) -> FlowInput {
    let (src, dst) = if from_client {
        (ep(CLIENT, 53214), ep(SERVER, 443))
    } else {
        (ep(SERVER, 443), ep(CLIENT, 53214))
    };
    FlowInput {
        ts_micros: ts,
        src,
        dst,
        proto: Proto::Tcp,
        wire_len: 54 + len,
        tcp: Some(TcpInfo {
            seq,
            ack,
            flags,
            window,
            payload_len: len,
        }),
    }
}

fn udp(ts: i64, from_a: bool, len: u32) -> FlowInput {
    let (src, dst) = if from_a {
        (ep(CLIENT, 5000), ep("8.8.8.8", 53))
    } else {
        (ep("8.8.8.8", 53), ep(CLIENT, 5000))
    };
    FlowInput {
        ts_micros: ts,
        src,
        dst,
        proto: Proto::Udp,
        wire_len: 42 + len,
        tcp: None,
    }
}

fn handshake(e: &mut FlowEngine, t0: i64) -> u64 {
    let id = e.observe(&tcp(t0, true, SYN, 1000, 0, 0));
    e.observe(&tcp(t0 + 20_000, false, SYN | ACK, 5000, 1001, 0));
    e.observe(&tcp(t0 + 20_500, true, ACK, 1001, 5001, 0));
    id
}

#[test]
fn both_directions_share_one_flow() {
    let mut e = FlowEngine::default();
    let a = e.observe(&udp(0, true, 30));
    let b = e.observe(&udp(10, false, 90));
    assert_eq!(a, b);
    assert_eq!(e.len(), 1);
    let f = e.get(a).unwrap();
    assert_eq!((f.packets_a_to_b, f.packets_b_to_a), (1, 1));
    assert_eq!((f.bytes_a_to_b, f.bytes_b_to_a), (72, 132));
    assert_eq!((f.total_packets(), f.total_bytes()), (2, 204));
}

#[test]
fn different_conversations_get_different_flows() {
    let mut e = FlowEngine::default();
    let a = e.observe(&udp(0, true, 1));
    let mut other = udp(0, true, 1);
    other.src.port = 5001;
    let b = e.observe(&other);
    assert_ne!(a, b);
    assert_eq!(e.len(), 2);
}

#[test]
fn endpoint_a_is_the_initiator() {
    let mut e = FlowEngine::default();
    let id = e.observe(&tcp(0, true, SYN, 1, 0, 0));
    e.observe(&tcp(1, false, SYN | ACK, 9, 2, 0));
    let f = e.get(id).unwrap();
    assert_eq!(f.endpoint_a, ep(CLIENT, 53214));
    assert_eq!(f.endpoint_b, ep(SERVER, 443));
}

#[test]
fn midstream_synack_first_marks_sender_as_server() {
    let mut e = FlowEngine::default();
    let id = e.observe(&tcp(0, false, SYN | ACK, 9, 2, 0));
    let f = e.get(id).unwrap();
    assert_eq!(f.endpoint_a, ep(CLIENT, 53214));
    assert_eq!(f.packets_b_to_a, 1);
}

#[test]
fn handshake_sets_state_and_rtt() {
    let mut e = FlowEngine::default();
    let id = handshake(&mut e, 5 * SEC);
    let f = e.get(id).unwrap();
    assert_eq!(f.tcp_state, Some(TcpState::Established));
    assert_eq!(f.handshake_rtt_micros, Some(20_000));
}

#[test]
fn state_progresses_through_the_handshake() {
    let mut e = FlowEngine::default();
    let id = e.observe(&tcp(0, true, SYN, 1000, 0, 0));
    assert_eq!(e.get(id).unwrap().tcp_state, Some(TcpState::SynSent));
    e.observe(&tcp(10, false, SYN | ACK, 5000, 1001, 0));
    assert_eq!(e.get(id).unwrap().tcp_state, Some(TcpState::SynReceived));
    e.observe(&tcp(20, true, ACK, 1001, 5001, 0));
    assert_eq!(e.get(id).unwrap().tcp_state, Some(TcpState::Established));
}

#[test]
fn graceful_close() {
    let mut e = FlowEngine::default();
    let id = handshake(&mut e, 0);
    e.observe(&tcp(SEC, true, FIN | ACK, 1001, 5001, 0));
    assert_eq!(e.get(id).unwrap().tcp_state, Some(TcpState::Closing));
    e.observe(&tcp(SEC + 10, false, ACK, 5001, 1002, 0));
    assert_eq!(e.get(id).unwrap().tcp_state, Some(TcpState::Closing));
    e.observe(&tcp(SEC + 20, false, FIN | ACK, 5001, 1002, 0));
    assert_eq!(e.get(id).unwrap().tcp_state, Some(TcpState::Closed));
    e.observe(&tcp(SEC + 30, true, ACK, 1002, 5002, 0));
    assert_eq!(e.get(id).unwrap().tcp_state, Some(TcpState::Closed));
    assert_eq!(e.get(id).unwrap().resets, 0);
}

#[test]
fn reset_is_counted_and_final() {
    let mut e = FlowEngine::default();
    let id = handshake(&mut e, 0);
    e.observe(&tcp(SEC, false, RST | ACK, 5001, 1001, 0));
    let f = e.get(id).unwrap();
    assert_eq!((f.resets, f.tcp_state), (1, Some(TcpState::Reset)));
}

#[test]
fn midstream_capture_is_established() {
    let mut e = FlowEngine::default();
    let id = e.observe(&tcp(0, true, ACK | PSH, 7000, 100, 500));
    assert_eq!(e.get(id).unwrap().tcp_state, Some(TcpState::Established));
}

#[test]
fn detects_retransmissions() {
    let mut e = FlowEngine::default();
    let id = handshake(&mut e, 0);
    e.observe(&tcp(SEC, true, ACK | PSH, 1001, 5001, 100));
    e.observe(&tcp(SEC + 1, true, ACK | PSH, 1101, 5001, 100));
    assert_eq!(e.get(id).unwrap().retransmissions, 0);
    e.observe(&tcp(SEC + 2, true, ACK | PSH, 1001, 5001, 100)); // old data again
    assert_eq!(e.get(id).unwrap().retransmissions, 1);
    e.observe(&tcp(SEC + 3, true, ACK | PSH, 1201, 5001, 100)); // new data
    assert_eq!(e.get(id).unwrap().retransmissions, 1);
}

#[test]
fn retransmitted_syn_counts() {
    let mut e = FlowEngine::default();
    let id = e.observe(&tcp(0, true, SYN, 1000, 0, 0));
    e.observe(&tcp(SEC, true, SYN, 1000, 0, 0));
    assert_eq!(e.get(id).unwrap().retransmissions, 1);
}

#[test]
fn retransmission_detection_survives_sequence_wraparound() {
    let mut e = FlowEngine::default();
    let id = e.observe(&tcp(0, true, ACK, u32::MAX - 49, 1, 100)); // ends at 50 after wrapping
    e.observe(&tcp(1, true, ACK, 50, 1, 100));
    assert_eq!(e.get(id).unwrap().retransmissions, 0);
    e.observe(&tcp(2, true, ACK, u32::MAX - 49, 1, 100));
    assert_eq!(e.get(id).unwrap().retransmissions, 1);
}

#[test]
fn keepalives_are_not_retransmissions() {
    let mut e = FlowEngine::default();
    let id = e.observe(&tcp(0, true, ACK, 1000, 1, 100));
    e.observe(&tcp(1, true, ACK, 1099, 1, 1)); // seq = next-1, 1 byte
    assert_eq!(e.get(id).unwrap().retransmissions, 0);
}

#[test]
fn out_of_order_gap_is_not_retransmission() {
    let mut e = FlowEngine::default();
    let id = e.observe(&tcp(0, true, ACK, 1000, 1, 100));
    e.observe(&tcp(1, true, ACK, 1300, 1, 100)); // skipped 1100..1300
    assert_eq!(e.get(id).unwrap().retransmissions, 0);
}

#[test]
fn directions_are_tracked_independently() {
    let mut e = FlowEngine::default();
    let id = e.observe(&tcp(0, true, ACK, 1000, 1, 100));
    e.observe(&tcp(1, false, ACK, 1000, 1101, 100)); // same numbers, other direction
    assert_eq!(e.get(id).unwrap().retransmissions, 0);
}

#[test]
fn duplicate_acks_and_zero_windows() {
    let mut e = FlowEngine::default();
    let id = e.observe(&tcp(0, false, ACK, 5000, 2000, 0));
    e.observe(&tcp(1, false, ACK, 5000, 2000, 0));
    e.observe(&tcp(2, false, ACK, 5000, 2000, 0));
    assert_eq!(e.get(id).unwrap().duplicate_acks, 2);
    e.observe(&tcp(3, false, ACK, 5000, 2100, 0)); // ack advanced
    assert_eq!(e.get(id).unwrap().duplicate_acks, 2);
    e.observe(&tcp_w(4, true, ACK, 1, 5000, 0, 0));
    assert_eq!(e.get(id).unwrap().zero_windows, 1);
}

#[test]
fn duration_and_ordering() {
    let mut e = FlowEngine::default();
    let id = e.observe(&udp(10 * SEC, true, 1));
    e.observe(&udp(12 * SEC, false, 1));
    e.observe(&udp(11 * SEC, true, 1)); // out-of-order timestamp
    let f = e.get(id).unwrap();
    assert_eq!(
        (f.started_at, f.last_seen_at, f.duration_micros()),
        (10 * SEC, 12 * SEC, 2 * SEC)
    );
}

#[test]
fn sparkline_buckets_bytes_per_second() {
    let mut e = FlowEngine::default();
    let id = e.observe(&udp(100 * SEC, true, 58)); // 100 bytes
    e.observe(&udp(100 * SEC + 5, false, 58));
    e.observe(&udp(102 * SEC, true, 58));
    let s = e.get(id).unwrap().sparkline();
    assert_eq!(s.len(), 60);
    assert_eq!(s[59], 100); // last second
    assert_eq!(s[57], 200); // two seconds earlier
    assert_eq!(s[58], 0);
}

#[test]
fn only_changed_flows_are_reported() {
    let mut e = FlowEngine::default();
    let a = e.observe(&udp(0, true, 1));
    let mut other = udp(0, true, 1);
    other.src.port = 6000;
    let b = e.observe(&other);
    assert_eq!(
        e.take_changed(usize::MAX)
            .iter()
            .map(|f| f.id)
            .collect::<Vec<_>>(),
        vec![a, b]
    );
    assert!(e.take_changed(usize::MAX).is_empty());
    e.observe(&udp(5, false, 1));
    let changed = e.take_changed(usize::MAX);
    assert_eq!(changed.len(), 1);
    assert_eq!(changed[0].id, a);
    assert_eq!(changed[0].packets_b_to_a, 1);
}

#[test]
fn flow_limit_evicts_the_least_recently_seen() {
    let mut e = FlowEngine::new(10);
    for i in 0..10u16 {
        let mut p = udp(i64::from(i), true, 1);
        p.src.port = 1000 + i;
        e.observe(&p);
    }
    assert_eq!(e.len(), 10);
    let mut p = udp(100, true, 1);
    p.src.port = 2000;
    e.observe(&p);
    assert_eq!(e.len(), 10);
    assert_eq!(e.evicted, 1);
    // the oldest flow (port 1000) is gone and would start over as a new flow
    let mut again = udp(200, true, 1);
    again.src.port = 1000;
    let id = e.observe(&again);
    assert_eq!(e.get(id).unwrap().total_packets(), 1);
}

#[test]
fn view_exposes_ui_fields() {
    let mut e = FlowEngine::default();
    let id = handshake(&mut e, 0);
    e.get_mut(id).unwrap().domains.push("api.github.com".into());
    let v = FlowView::of(e.get(id).unwrap());
    assert_eq!(v.protocol, "TCP");
    assert_eq!(v.application_protocol.as_deref(), Some("TLS"));
    assert_eq!(v.latency, Some(20_000));
    assert_eq!(v.domains, vec!["api.github.com"]);
    assert!(v.process.is_none());
    let json = serde_json::to_value(&v).unwrap();
    assert_eq!(json["tcpState"], "ESTABLISHED");
    assert_eq!(json["endpointA"]["ip"], CLIENT);
    assert_eq!(json["totalPackets"], 3);
}

#[test]
fn clear_resets_everything() {
    let mut e = FlowEngine::default();
    handshake(&mut e, 0);
    e.clear();
    assert!(e.is_empty());
    assert_eq!(e.observe(&udp(0, true, 1)), 1);
}

#[test]
fn builds_input_from_real_frames() {
    use etherparse::PacketBuilder;
    let b = PacketBuilder::ethernet2([1; 6], [2; 6])
        .ipv4([10, 0, 0, 1], [10, 0, 0, 2], 64)
        .tcp(40000, 80, 77, 1000)
        .syn();
    let mut data = vec![];
    b.write(&mut data, &[]).unwrap();
    let raw = RawPacket {
        id: 1,
        ts_micros: 42,
        captured_len: data.len() as u32,
        original_len: data.len() as u32,
        data,
    };
    let d = dissect(&raw.data);
    let input = FlowInput::from_dissection(&raw, &d).unwrap();
    assert_eq!(
        (input.proto, input.src.port, input.dst.port),
        (Proto::Tcp, 40000, 80)
    );
    assert_eq!(input.tcp.unwrap().seq, 77);
    assert_eq!(summarize(&raw).source_ip.as_deref(), Some("10.0.0.1"));

    // ARP and garbage produce no flow input
    let mut arp = vec![0xff; 6];
    arp.extend([1, 2, 3, 4, 5, 6, 8, 6]);
    arp.extend([
        0, 1, 8, 0, 6, 4, 0, 1, 1, 2, 3, 4, 5, 6, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 2, 2, 2, 2,
    ]);
    let raw = RawPacket {
        id: 2,
        ts_micros: 0,
        captured_len: arp.len() as u32,
        original_len: arp.len() as u32,
        data: arp,
    };
    assert!(FlowInput::from_dissection(&raw, &dissect(&raw.data)).is_none());
    let junk = RawPacket {
        id: 3,
        ts_micros: 0,
        captured_len: 3,
        original_len: 3,
        data: vec![1, 2, 3],
    };
    assert!(FlowInput::from_dissection(&junk, &dissect(&junk.data)).is_none());
}

#[test]
fn syn_after_close_starts_a_new_flow_but_stray_packets_do_not() {
    let mut e = FlowEngine::default();
    let first = handshake(&mut e, 0);
    e.observe(&tcp(SEC, true, FIN | ACK, 1001, 5001, 0));
    e.observe(&tcp(SEC + 10, false, FIN | ACK, 5001, 1002, 0));
    assert_eq!(e.get(first).unwrap().tcp_state, Some(TcpState::Closed));
    // a late ACK of the old connection stays in the old flow
    assert_eq!(e.observe(&tcp(SEC + 20, true, ACK, 1002, 5002, 0)), first);
    // a brand new SYN on the same 5-tuple is a new conversation
    let second = e.observe(&tcp(10 * SEC, true, SYN, 77_000, 0, 0));
    assert_ne!(second, first);
    assert_eq!(e.get(second).unwrap().tcp_state, Some(TcpState::SynSent));
    assert_eq!(e.get(second).unwrap().packets_a_to_b, 1);
    // the finished flow is left untouched
    assert_eq!(e.get(first).unwrap().tcp_state, Some(TcpState::Closed));
    assert_eq!(e.len(), 2);
    // and later traffic follows the new flow
    assert_eq!(
        e.observe(&tcp(10 * SEC + 1, false, SYN | ACK, 9, 77_001, 0)),
        second
    );
}

#[test]
fn syn_after_reset_starts_a_new_flow_and_retransmitted_syn_does_not() {
    let mut e = FlowEngine::default();
    let first = e.observe(&tcp(0, true, SYN, 1000, 0, 0));
    assert_eq!(e.observe(&tcp(SEC, true, SYN, 1000, 0, 0)), first); // retransmission, still connecting
    e.observe(&tcp(2 * SEC, false, RST | ACK, 0, 1001, 0));
    assert_eq!(e.get(first).unwrap().tcp_state, Some(TcpState::Reset));
    assert_ne!(e.observe(&tcp(3 * SEC, true, SYN, 5000, 0, 0)), first);
}

#[test]
fn udp_after_a_long_silence_is_a_new_conversation() {
    let mut e = FlowEngine::default();
    let a = e.observe(&udp(0, true, 10));
    assert_eq!(e.observe(&udp(60 * SEC, false, 10)), a); // within the idle gap
    let b = e.observe(&udp(60 * SEC + 121 * SEC, true, 10));
    assert_ne!(a, b);
    assert_eq!(e.get(b).unwrap().total_packets(), 1);
    assert_eq!(e.get(a).unwrap().total_packets(), 2);
    // a late-arriving old timestamp doesn't spawn flows
    assert_eq!(e.observe(&udp(0, true, 10)), b);
}

#[test]
fn evicting_an_old_flow_does_not_unmap_the_newer_flow_with_the_same_tuple() {
    let mut e = FlowEngine::new(3);
    let old = e.observe(&udp(0, true, 10));
    let newer = e.observe(&udp(200 * SEC, true, 10)); // same tuple after the idle gap
    assert_ne!(old, newer);
    for port in 0..2u16 {
        let mut other = udp(300 * SEC, true, 1);
        other.src.port = 7000 + port;
        e.observe(&other);
    }
    // the table was full: the oldest flow (`old`) is gone, `newer` is still reachable by its tuple
    assert!(e.get(old).is_none());
    assert_eq!(e.observe(&udp(301 * SEC, true, 10)), newer);
}

#[test]
fn drains_are_capped_and_resume_where_they_left_off() {
    let mut e = FlowEngine::default();
    for port in 0..25u16 {
        let mut p = udp(0, true, 1);
        p.src.port = 1000 + port;
        e.observe(&p);
    }
    let first = e.take_changed(10);
    let second = e.take_changed(10);
    let third = e.take_changed(10);
    assert_eq!((first.len(), second.len(), third.len()), (10, 10, 5));
    assert!(e.take_changed(10).is_empty());
    let mut ids: Vec<u64> = [first, second, third]
        .concat()
        .iter()
        .map(|f| f.id)
        .collect();
    ids.sort_unstable();
    assert_eq!(ids, (1..=25).collect::<Vec<_>>());
}

#[test]
fn packets_with_unreadable_transport_headers_get_no_flow() {
    use etherparse::PacketBuilder;
    let b = PacketBuilder::ethernet2([1; 6], [2; 6])
        .ipv4([10, 0, 0, 1], [10, 0, 0, 2], 64)
        .tcp(40000, 80, 1, 1000);
    let mut full = vec![];
    b.write(&mut full, &[]).unwrap();
    for cut in [full.len() - 1, 14 + 20 + 5, 14 + 20 + 1] {
        let data = full[..cut].to_vec();
        let raw = RawPacket {
            id: 1,
            ts_micros: 0,
            captured_len: cut as u32,
            original_len: full.len() as u32,
            data,
        };
        assert!(
            FlowInput::from_dissection(&raw, &dissect(&raw.data)).is_none(),
            "cut at {cut}"
        );
    }
    // a complete header is still tracked
    let raw = RawPacket {
        id: 1,
        ts_micros: 0,
        captured_len: full.len() as u32,
        original_len: full.len() as u32,
        data: full,
    };
    assert!(FlowInput::from_dissection(&raw, &dissect(&raw.data)).is_some());
}
