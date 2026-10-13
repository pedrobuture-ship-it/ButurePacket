use crate::util::LockRecover;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use serde::Serialize;

use super::error::CaptureError;
use super::packet::RawPacket;
use super::source::PacketSource;
use super::stats::{Counters, RateTracker, StatsSnapshot};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum SessionState {
    Idle,
    Running,
    Paused,
    Stopped,
    Error,
}

#[derive(Debug, Clone)]
pub struct SessionConfig {
    /// Hard cap on bytes buffered between the reader and the batcher.
    pub max_buffer_bytes: usize,
    /// How often buffered packets are flushed to the sink (30–100ms).
    pub batch_interval: Duration,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            max_buffer_bytes: 64 * 1024 * 1024,
            batch_interval: Duration::from_millis(50),
        }
    }
}

/// Receives everything the session produces. Implementations must be cheap and non-blocking.
pub trait CaptureSink: Send + Sync + 'static {
    fn on_batch(&self, packets: Vec<RawPacket>);
    fn on_stats(&self, stats: &StatsSnapshot);
    fn on_state(&self, state: SessionState, error: Option<&CaptureError>);
}

#[derive(Default)]
struct Buffer {
    packets: VecDeque<RawPacket>,
    bytes: usize,
}

struct Shared {
    config: SessionConfig,
    state: Mutex<(SessionState, Option<CaptureError>)>,
    buffer: Mutex<Buffer>,
    counters: Counters,
    stop: AtomicBool,
    reader_done: AtomicBool,
    wake: (Mutex<()>, Condvar),
}

impl Shared {
    fn set_state(&self, next: SessionState, err: Option<CaptureError>, sink: &dyn CaptureSink) {
        {
            let mut s = self.state.lock_recover();
            *s = (next, err.clone());
        }
        sink.on_state(next, err.as_ref());
    }
}

pub struct CaptureSession {
    shared: Arc<Shared>,
    sink: Arc<dyn CaptureSink>,
    threads: Vec<JoinHandle<()>>,
}

impl CaptureSession {
    /// Starts reading from `source` on background threads and returns immediately.
    pub fn start(
        source: Box<dyn PacketSource>,
        sink: Arc<dyn CaptureSink>,
        config: SessionConfig,
    ) -> Self {
        let shared = Arc::new(Shared {
            config,
            state: Mutex::new((SessionState::Running, None)),
            buffer: Mutex::new(Buffer::default()),
            counters: Counters::default(),
            stop: AtomicBool::new(false),
            reader_done: AtomicBool::new(false),
            wake: (Mutex::new(()), Condvar::new()),
        });
        sink.on_state(SessionState::Running, None);
        let reader = {
            let (s, k) = (shared.clone(), sink.clone());
            thread::Builder::new()
                .name("capture-reader".into())
                .spawn(move || reader_loop(source, &s, &*k))
                .expect("spawn reader")
        };
        let batcher = {
            let (s, k) = (shared.clone(), sink.clone());
            thread::Builder::new()
                .name("capture-batcher".into())
                .spawn(move || batcher_loop(&s, &*k))
                .expect("spawn batcher")
        };
        Self {
            shared,
            sink,
            threads: vec![reader, batcher],
        }
    }

    pub fn state(&self) -> SessionState {
        self.shared.state.lock_recover().0
    }

    pub fn pause(&self) -> Result<(), CaptureError> {
        self.transition(SessionState::Running, SessionState::Paused)
    }

    pub fn resume(&self) -> Result<(), CaptureError> {
        self.transition(SessionState::Paused, SessionState::Running)
    }

    fn transition(&self, from: SessionState, to: SessionState) -> Result<(), CaptureError> {
        {
            let mut s = self.shared.state.lock_recover();
            if s.0 != from {
                return Err(CaptureError::NotRunning);
            }
            s.0 = to;
        }
        self.sink.on_state(to, None);
        Ok(())
    }

    /// Stops the capture, flushes whatever is buffered and joins the worker threads.
    pub fn stop(&mut self) {
        self.shared.stop.store(true, Ordering::SeqCst);
        self.shared.wake.1.notify_all();
        for t in self.threads.drain(..) {
            let _ = t.join();
        }
        let current = self.state();
        if matches!(current, SessionState::Running | SessionState::Paused) {
            self.shared
                .set_state(SessionState::Stopped, None, &*self.sink);
        }
    }
}

impl Drop for CaptureSession {
    fn drop(&mut self) {
        self.stop();
    }
}

fn reader_loop(mut source: Box<dyn PacketSource>, shared: &Shared, sink: &dyn CaptureSink) {
    let mut next_id = 1u64;
    let mut last_kernel_poll = Instant::now();
    while !shared.stop.load(Ordering::Relaxed) {
        match source.next_packet() {
            Ok(Some(mut packet)) => {
                if shared.state.lock_recover().0 != SessionState::Running {
                    continue; // paused: read and discard so the kernel buffer doesn't overflow
                }
                let size = packet.mem_size();
                let mut buf = shared.buffer.lock_recover();
                if buf.bytes + size > shared.config.max_buffer_bytes {
                    shared
                        .counters
                        .dropped_buffer
                        .fetch_add(1, Ordering::Relaxed);
                    continue;
                }
                packet.id = next_id;
                next_id += 1;
                buf.bytes += size;
                shared.counters.packets.fetch_add(1, Ordering::Relaxed);
                shared
                    .counters
                    .bytes
                    .fetch_add(u64::from(packet.captured_len), Ordering::Relaxed);
                buf.packets.push_back(packet);
                shared
                    .counters
                    .buffer_bytes
                    .store(buf.bytes as u64, Ordering::Relaxed);
            }
            Ok(None) => {}
            Err(CaptureError::EndOfStream) => break,
            Err(e) => {
                shared.set_state(SessionState::Error, Some(e), sink);
                break;
            }
        }
        if last_kernel_poll.elapsed() >= Duration::from_secs(1) {
            shared
                .counters
                .dropped_kernel
                .store(source.kernel_dropped(), Ordering::Relaxed);
            last_kernel_poll = Instant::now();
        }
    }
    shared
        .counters
        .dropped_kernel
        .store(source.kernel_dropped(), Ordering::Relaxed);
    shared.reader_done.store(true, Ordering::SeqCst);
    shared.wake.1.notify_all();
}

fn batcher_loop(shared: &Shared, sink: &dyn CaptureSink) {
    let mut rates = RateTracker::new(Duration::from_secs(1));
    let started = Instant::now();
    let mut running_time = Duration::ZERO;
    let mut busy = Duration::ZERO;
    let mut last_tick = Instant::now();
    let mut load = 0.0f64;

    loop {
        {
            let guard = shared.wake.0.lock_recover();
            if !shared.reader_done.load(Ordering::SeqCst) {
                let _ = shared
                    .wake
                    .1
                    .wait_timeout(guard, shared.config.batch_interval)
                    .unwrap();
            }
        }
        let now = Instant::now();
        let tick = now.duration_since(last_tick);
        last_tick = now;
        if shared.state.lock_recover().0 == SessionState::Running {
            running_time += tick;
        }

        let batch: Vec<RawPacket> = {
            let mut buf = shared.buffer.lock_recover();
            buf.bytes = 0;
            shared.counters.buffer_bytes.store(0, Ordering::Relaxed);
            buf.packets.drain(..).collect()
        };
        if !batch.is_empty() {
            let t = Instant::now();
            sink.on_batch(batch);
            busy += t.elapsed();
        }
        if tick > Duration::ZERO {
            let instant_load = (busy.as_secs_f64() / tick.as_secs_f64()).min(1.0);
            load = load * 0.8 + instant_load * 0.2;
            busy = Duration::ZERO;
        }

        let packets = shared.counters.packets.load(Ordering::Relaxed);
        let bytes = shared.counters.bytes.load(Ordering::Relaxed);
        let (pps, bps) = rates.update(now, packets, bytes);
        sink.on_stats(&StatsSnapshot {
            packets,
            bytes,
            dropped: shared.counters.dropped(),
            packets_per_sec: pps,
            bytes_per_sec: bps,
            buffer_bytes: shared.counters.buffer_bytes.load(Ordering::Relaxed),
            parser_load: load,
            duration_ms: running_time.as_millis() as u64,
        });

        if shared.reader_done.load(Ordering::SeqCst)
            && shared.buffer.lock_recover().packets.is_empty()
        {
            break;
        }
    }
    let _ = started;
    let (state, err) = shared.state.lock_recover().clone();
    if matches!(state, SessionState::Running | SessionState::Paused) {
        // Reader ended on its own (finite source): the capture is complete.
        shared.set_state(SessionState::Stopped, err, sink);
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;

    /// Scripted packet source for tests.
    pub struct MockSource {
        pub packets: VecDeque<RawPacket>,
        /// When the queue empties: end the stream (`true`) or idle like a live capture (`false`).
        pub finite: bool,
        pub fail_with: Option<CaptureError>,
    }

    pub fn pkt(len: usize) -> RawPacket {
        RawPacket {
            id: 0,
            ts_micros: 1,
            captured_len: len as u32,
            original_len: len as u32,
            data: vec![0u8; len],
        }
    }

    impl PacketSource for MockSource {
        fn next_packet(&mut self) -> Result<Option<RawPacket>, CaptureError> {
            if let Some(p) = self.packets.pop_front() {
                return Ok(Some(p));
            }
            if let Some(e) = self.fail_with.take() {
                return Err(e);
            }
            if self.finite {
                return Err(CaptureError::EndOfStream);
            }
            thread::sleep(Duration::from_millis(2));
            Ok(None)
        }
    }

    #[derive(Default)]
    pub struct TestSink {
        pub received: Mutex<Vec<RawPacket>>,
        pub batches: AtomicUsize,
        pub states: Mutex<Vec<SessionState>>,
        pub last_stats: Mutex<Option<StatsSnapshot>>,
    }

    impl CaptureSink for TestSink {
        fn on_batch(&self, packets: Vec<RawPacket>) {
            self.batches.fetch_add(1, Ordering::SeqCst);
            self.received.lock_recover().extend(packets);
        }
        fn on_stats(&self, stats: &StatsSnapshot) {
            *self.last_stats.lock_recover() = Some(stats.clone());
        }
        fn on_state(&self, state: SessionState, _: Option<&CaptureError>) {
            self.states.lock_recover().push(state);
        }
    }

    fn wait_until(mut cond: impl FnMut() -> bool) {
        let t = Instant::now();
        while !cond() {
            assert!(t.elapsed() < Duration::from_secs(5), "timed out");
            thread::sleep(Duration::from_millis(5));
        }
    }

    fn source(n: usize, len: usize, finite: bool) -> Box<MockSource> {
        Box::new(MockSource {
            packets: (0..n).map(|_| pkt(len)).collect(),
            finite,
            fail_with: None,
        })
    }

    #[test]
    fn finite_source_delivers_everything_in_order_then_stops() {
        let sink = Arc::new(TestSink::default());
        let mut s = CaptureSession::start(
            source(500, 64, true),
            sink.clone(),
            SessionConfig::default(),
        );
        wait_until(|| s.state() == SessionState::Stopped);
        s.stop();
        let got = sink.received.lock_recover();
        assert_eq!(got.len(), 500);
        assert!(got.iter().enumerate().all(|(i, p)| p.id == i as u64 + 1));
        let stats = sink.last_stats.lock_recover().clone().unwrap();
        assert_eq!(stats.packets, 500);
        assert_eq!(stats.bytes, 500 * 64);
        assert_eq!(stats.dropped, 0);
    }

    #[test]
    fn packets_are_batched_not_sent_one_by_one() {
        let sink = Arc::new(TestSink::default());
        let mut s = CaptureSession::start(
            source(2000, 32, true),
            sink.clone(),
            SessionConfig::default(),
        );
        wait_until(|| s.state() == SessionState::Stopped);
        s.stop();
        assert_eq!(sink.received.lock_recover().len(), 2000);
        assert!(
            sink.batches.load(Ordering::SeqCst) < 200,
            "expected batching"
        );
    }

    #[test]
    fn pause_discards_and_resume_continues() {
        let sink = Arc::new(TestSink::default());
        let src = Box::new(MockSource {
            packets: VecDeque::new(),
            finite: false,
            fail_with: None,
        });
        let mut s = CaptureSession::start(src, sink.clone(), SessionConfig::default());
        assert_eq!(s.state(), SessionState::Running);
        s.pause().unwrap();
        assert_eq!(s.state(), SessionState::Paused);
        assert_eq!(s.pause(), Err(CaptureError::NotRunning));
        s.resume().unwrap();
        assert_eq!(s.resume(), Err(CaptureError::NotRunning));
        s.stop();
        assert_eq!(s.state(), SessionState::Stopped);
        let states = sink.states.lock_recover().clone();
        assert_eq!(
            states,
            vec![
                SessionState::Running,
                SessionState::Paused,
                SessionState::Running,
                SessionState::Stopped
            ]
        );
    }

    #[test]
    fn buffer_limit_drops_and_counts() {
        let sink = Arc::new(TestSink::default());
        let cfg = SessionConfig {
            max_buffer_bytes: 10 * 1024,
            batch_interval: Duration::from_secs(10),
        };
        let mut s = CaptureSession::start(source(100, 1000, true), sink.clone(), cfg);
        wait_until(|| s.shared.reader_done.load(Ordering::SeqCst));
        let dropped = s.shared.counters.dropped();
        s.stop();
        assert!(dropped > 0);
        let accepted = sink.received.lock_recover().len() as u64;
        assert_eq!(accepted + dropped, 100);
    }

    #[test]
    fn source_error_moves_session_to_error_state() {
        let sink = Arc::new(TestSink::default());
        let src = Box::new(MockSource {
            packets: VecDeque::new(),
            finite: false,
            fail_with: Some(CaptureError::PermissionDenied),
        });
        let mut s = CaptureSession::start(src, sink.clone(), SessionConfig::default());
        wait_until(|| s.state() == SessionState::Error);
        s.stop();
        assert_eq!(s.state(), SessionState::Error);
    }

    #[test]
    fn stop_flushes_buffered_packets() {
        let sink = Arc::new(TestSink::default());
        let cfg = SessionConfig {
            max_buffer_bytes: 1 << 20,
            batch_interval: Duration::from_secs(10),
        };
        let mut s = CaptureSession::start(source(50, 10, false), sink.clone(), cfg);
        wait_until(|| s.shared.counters.packets.load(Ordering::SeqCst) == 50);
        s.stop();
        assert_eq!(sink.received.lock_recover().len(), 50);
    }
}
