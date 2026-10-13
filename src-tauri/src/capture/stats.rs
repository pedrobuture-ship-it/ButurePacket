use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use serde::Serialize;

/// Lock-free counters shared between the reader and batcher threads.
#[derive(Debug, Default)]
pub struct Counters {
    pub packets: AtomicU64,
    pub bytes: AtomicU64,
    /// Packets rejected because the in-memory buffer was full.
    pub dropped_buffer: AtomicU64,
    /// Packets the kernel/driver dropped before we could read them.
    pub dropped_kernel: AtomicU64,
    pub buffer_bytes: AtomicU64,
}

impl Counters {
    pub fn dropped(&self) -> u64 {
        self.dropped_buffer.load(Ordering::Relaxed) + self.dropped_kernel.load(Ordering::Relaxed)
    }
}

#[derive(Debug, Clone, Default, Serialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct StatsSnapshot {
    pub packets: u64,
    pub dropped: u64,
    pub bytes: u64,
    pub packets_per_sec: f64,
    pub bytes_per_sec: f64,
    pub buffer_bytes: u64,
    /// Fraction (0..1) of wall time spent processing batches.
    pub parser_load: f64,
    pub duration_ms: u64,
}

/// Computes per-second rates over a sliding window of ~1s.
#[derive(Debug)]
pub struct RateTracker {
    window: Duration,
    samples: VecDeque<(Instant, u64, u64)>,
}

impl RateTracker {
    pub fn new(window: Duration) -> Self {
        Self {
            window,
            samples: VecDeque::new(),
        }
    }

    pub fn update(&mut self, now: Instant, packets: u64, bytes: u64) -> (f64, f64) {
        self.samples.push_back((now, packets, bytes));
        // Keep the newest sample that is at least `window` old as the baseline.
        while self.samples.len() > 2 && now.duration_since(self.samples[1].0) >= self.window {
            self.samples.pop_front();
        }
        let (t0, p0, b0) = self.samples[0];
        let dt = now.duration_since(t0).as_secs_f64();
        if dt <= f64::EPSILON {
            return (0.0, 0.0);
        }
        (
            packets.saturating_sub(p0) as f64 / dt,
            bytes.saturating_sub(b0) as f64 / dt,
        )
    }

    pub fn reset(&mut self) {
        self.samples.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rate_over_window() {
        let mut r = RateTracker::new(Duration::from_secs(1));
        let t = Instant::now();
        r.update(t, 0, 0);
        let (pps, bps) = r.update(t + Duration::from_millis(500), 500, 50_000);
        assert!((pps - 1000.0).abs() < 1.0);
        assert!((bps - 100_000.0).abs() < 1.0);
    }

    #[test]
    fn single_sample_has_zero_rate() {
        let mut r = RateTracker::new(Duration::from_secs(1));
        assert_eq!(r.update(Instant::now(), 10, 10), (0.0, 0.0));
    }

    #[test]
    fn counters_sum_drops() {
        let c = Counters::default();
        c.dropped_buffer.store(3, Ordering::Relaxed);
        c.dropped_kernel.store(4, Ordering::Relaxed);
        assert_eq!(c.dropped(), 7);
    }
}
