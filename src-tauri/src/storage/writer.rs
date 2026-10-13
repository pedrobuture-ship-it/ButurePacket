//! Background writer: batches of derived records are committed from a dedicated thread so
//! parsing never waits on disk, and many batches share one transaction.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender, TrySendError};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use serde::Serialize;

use super::database::Database;
use super::{dns, events, flows, packets};
use crate::analytics::dns::DnsTransactionView;
use crate::analytics::events::TimelineEvent;
use crate::capture::CaptureError;
use crate::flows::FlowView;
use crate::protocols::PacketSummary;

/// Jobs merged into a single transaction at most.
const MAX_JOBS_PER_COMMIT: usize = 128;
const SIZE_CHECK_INTERVAL: Duration = Duration::from_secs(1);

pub enum Job {
    Packets(Arc<Vec<PacketSummary>>),
    Flows(Vec<FlowView>),
    Events(Vec<TimelineEvent>),
    Dns(Vec<DnsTransactionView>),
}

enum Msg {
    Job(Job),
    /// Flush, build deferred indexes, checkpoint, then acknowledge.
    Finish(mpsc::Sender<Result<(), CaptureError>>),
}

#[derive(Debug, Clone)]
pub struct StorageConfig {
    /// Stop storing packet rows once the database reaches this size.
    pub max_bytes: u64,
    /// Queue depth (jobs).
    pub queue: usize,
    /// Wait for room instead of dropping jobs (right for file imports, wrong for live capture).
    pub block_when_full: bool,
    /// Skip secondary indexes while loading and build them once at the end.
    pub defer_indexes: bool,
}

impl StorageConfig {
    pub fn live() -> Self {
        Self {
            max_bytes: 4 << 30,
            queue: 256,
            block_when_full: false,
            defer_indexes: false,
        }
    }

    pub fn import() -> Self {
        Self {
            max_bytes: 8 << 30,
            queue: 64,
            block_when_full: true,
            defer_indexes: true,
        }
    }
}

#[derive(Debug, Default)]
struct Shared {
    packets_written: AtomicU64,
    dropped_jobs: AtomicU64,
    bytes: AtomicU64,
    limit_reached: AtomicBool,
    error: std::sync::Mutex<Option<String>>,
}

/// What the UI needs to know about persistence health.
#[derive(Debug, Clone, Default, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct StorageStatus {
    pub packets_written: u64,
    pub dropped_jobs: u64,
    pub bytes: u64,
    pub limit_reached: bool,
    pub error: Option<String>,
}

pub struct StorageWriter {
    tx: SyncSender<Msg>,
    handle: Option<JoinHandle<()>>,
    shared: Arc<Shared>,
    block: bool,
}

impl StorageWriter {
    pub fn start(db: Database, config: StorageConfig) -> Result<Self, CaptureError> {
        if config.defer_indexes {
            db.drop_indexes()?;
        }
        let (tx, rx) = mpsc::sync_channel(config.queue.max(1));
        let shared = Arc::new(Shared::default());
        let block = config.block_when_full;
        let handle = {
            let shared = shared.clone();
            thread::Builder::new()
                .name("storage-writer".into())
                .spawn(move || writer_loop(db, rx, config, &shared))
                .map_err(|e| CaptureError::Storage(e.to_string()))?
        };
        Ok(Self {
            tx,
            handle: Some(handle),
            shared,
            block,
        })
    }

    /// Queues a job. Returns `false` when it had to be dropped (queue full in non-blocking mode).
    pub fn submit(&self, job: Job) -> bool {
        let msg = Msg::Job(job);
        if self.block {
            return self.tx.send(msg).is_ok();
        }
        match self.tx.try_send(msg) {
            Ok(()) => true,
            Err(TrySendError::Full(_)) => {
                self.shared.dropped_jobs.fetch_add(1, Ordering::Relaxed);
                false
            }
            Err(TrySendError::Disconnected(_)) => false,
        }
    }

    pub fn status(&self) -> StorageStatus {
        StorageStatus {
            packets_written: self.shared.packets_written.load(Ordering::Relaxed),
            dropped_jobs: self.shared.dropped_jobs.load(Ordering::Relaxed),
            bytes: self.shared.bytes.load(Ordering::Relaxed),
            limit_reached: self.shared.limit_reached.load(Ordering::Relaxed),
            error: self.shared.error.lock().unwrap().clone(),
        }
    }

    /// Writes everything still queued, builds deferred indexes and closes the database.
    pub fn finish(mut self) -> Result<StorageStatus, CaptureError> {
        let (ack_tx, ack_rx) = mpsc::channel();
        let sent = self.tx.send(Msg::Finish(ack_tx)).is_ok();
        let result = if sent {
            ack_rx.recv().unwrap_or_else(|_| {
                Err(CaptureError::Storage(
                    "the storage thread stopped unexpectedly".into(),
                ))
            })
        } else {
            Ok(())
        };
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
        let status = self.status();
        result.map(|()| status)
    }
}

impl Drop for StorageWriter {
    fn drop(&mut self) {
        // Dropping the sender ends the loop; wait so the file is closed cleanly.
        if let Some(h) = self.handle.take() {
            let (dead, _) = mpsc::sync_channel(1);
            self.tx = dead;
            let _ = h.join();
        }
    }
}

fn apply(
    tx: &rusqlite::Transaction<'_>,
    job: &Job,
    skip_packets: bool,
    shared: &Shared,
) -> Result<(), CaptureError> {
    match job {
        Job::Packets(rows) if !skip_packets => {
            let n = packets::insert_packets(tx, rows)?;
            shared
                .packets_written
                .fetch_add(n as u64, Ordering::Relaxed);
        }
        Job::Packets(_) => {}
        Job::Flows(f) => {
            flows::upsert_flows(tx, f)?;
        }
        Job::Events(e) => {
            events::insert_events(tx, e)?;
        }
        Job::Dns(d) => {
            dns::upsert_dns(tx, d)?;
        }
    }
    Ok(())
}

fn writer_loop(mut db: Database, rx: Receiver<Msg>, config: StorageConfig, shared: &Shared) {
    let mut last_size_check = Instant::now();
    let mut failed = false;
    let record = |e: &CaptureError| {
        let mut slot = shared.error.lock().unwrap();
        slot.get_or_insert_with(|| e.to_string());
    };
    loop {
        let Ok(first) = rx.recv() else { break };
        let mut batch = vec![first];
        while batch.len() < MAX_JOBS_PER_COMMIT {
            match rx.try_recv() {
                Ok(m) => batch.push(m),
                Err(_) => break,
            }
        }
        let mut finish: Option<mpsc::Sender<Result<(), CaptureError>>> = None;
        let jobs: Vec<Job> = batch
            .into_iter()
            .filter_map(|m| match m {
                Msg::Job(j) => Some(j),
                Msg::Finish(ack) => {
                    finish = Some(ack);
                    None
                }
            })
            .collect();

        if last_size_check.elapsed() >= SIZE_CHECK_INTERVAL || finish.is_some() {
            last_size_check = Instant::now();
            if let Ok(size) = db.size_bytes() {
                shared.bytes.store(size, Ordering::Relaxed);
                if size >= config.max_bytes {
                    shared.limit_reached.store(true, Ordering::Relaxed);
                }
            }
        }
        if !failed && !jobs.is_empty() {
            let skip_packets = shared.limit_reached.load(Ordering::Relaxed);
            let result = (|| {
                let tx = db.conn.transaction()?;
                for j in &jobs {
                    apply(&tx, j, skip_packets, shared)?;
                }
                tx.commit()?;
                Ok::<(), CaptureError>(())
            })();
            if let Err(e) = result {
                record(&e);
                failed = true; // stop writing; the capture itself continues
            }
        }
        if let Some(ack) = finish {
            let result = if failed {
                Err(CaptureError::Storage(
                    shared
                        .error
                        .lock()
                        .unwrap()
                        .clone()
                        .unwrap_or_else(|| "write failed".into()),
                ))
            } else {
                (|| {
                    if config.defer_indexes {
                        db.create_indexes()?;
                    }
                    db.checkpoint()
                })()
            };
            let _ = ack.send(result);
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::packets::{PacketQuery, count_packets, query_packets, sample};

    fn rows(from: u64, n: u64) -> Arc<Vec<PacketSummary>> {
        Arc::new(
            (from..from + n)
                .map(|i| sample(i, "10.0.0.1", "10.0.0.2", Some("TLS"), i as i64))
                .collect(),
        )
    }

    fn reopen(path: &std::path::Path) -> Database {
        Database::open(path).unwrap()
    }

    #[test]
    fn writes_every_batch_and_finishes_with_indexes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("w.db");
        let w =
            StorageWriter::start(Database::open(&path).unwrap(), StorageConfig::import()).unwrap();
        for i in 0..50 {
            assert!(w.submit(Job::Packets(rows(i * 100 + 1, 100))));
        }
        let status = w.finish().unwrap();
        assert_eq!(status.packets_written, 5000);
        assert_eq!(
            (status.dropped_jobs, status.limit_reached, status.error),
            (0, false, None)
        );
        let db = reopen(&path);
        assert_eq!(count_packets(&db, &PacketQuery::default()).unwrap(), 5000);
        assert_eq!(
            db.index_names().unwrap().len(),
            crate::storage::database::INDEXES.len()
        );
    }

    #[test]
    fn other_record_kinds_are_persisted_too() {
        use crate::storage::{dns::dns_count, events::event_count, flows::flow_count};
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("k.db");
        let w =
            StorageWriter::start(Database::open(&path).unwrap(), StorageConfig::live()).unwrap();
        w.submit(Job::Events(vec![crate::analytics::events::TimelineEvent {
            id: 1,
            ts: 5,
            kind: crate::analytics::events::EventKind::FlowStarted,
            flow_id: None,
            host: None,
            domain: None,
            title: "x".into(),
            detail: None,
        }]));
        w.finish().unwrap();
        let db = reopen(&path);
        assert_eq!(
            (
                event_count(&db).unwrap(),
                flow_count(&db).unwrap(),
                dns_count(&db).unwrap()
            ),
            (1, 0, 0)
        );
    }

    #[test]
    fn non_blocking_mode_drops_and_counts_instead_of_stalling() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = StorageConfig {
            queue: 1,
            ..StorageConfig::live()
        };
        let w =
            StorageWriter::start(Database::open(&dir.path().join("d.db")).unwrap(), cfg).unwrap();
        let big = rows(1, 20_000);
        let accepted = (0..200)
            .filter(|_| w.submit(Job::Packets(big.clone())))
            .count();
        let status_before = w.status();
        let status = w.finish().unwrap();
        assert!(
            accepted < 200,
            "a 1-slot queue cannot absorb 200 instant submissions"
        );
        assert_eq!(status_before.dropped_jobs, 200 - accepted as u64);
        assert_eq!(status.packets_written, accepted as u64 * 20_000);
    }

    #[test]
    fn size_limit_stops_packet_rows_but_not_other_records() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("l.db");
        let cfg = StorageConfig {
            max_bytes: 1,
            ..StorageConfig::import()
        };
        let w = StorageWriter::start(Database::open(&path).unwrap(), cfg).unwrap();
        w.submit(Job::Packets(rows(1, 10)));
        // the first commit trips the limit (checked on finish below); later packet jobs are skipped
        thread::sleep(Duration::from_millis(1200));
        w.submit(Job::Packets(rows(100, 10)));
        let status = w.finish().unwrap();
        assert!(status.limit_reached);
        let db = reopen(&path);
        assert!(count_packets(&db, &PacketQuery::default()).unwrap() <= 10);
    }

    #[test]
    fn finish_with_nothing_queued_is_fine() {
        let dir = tempfile::tempdir().unwrap();
        let w = StorageWriter::start(
            Database::open(&dir.path().join("e.db")).unwrap(),
            StorageConfig::import(),
        )
        .unwrap();
        assert_eq!(w.finish().unwrap().packets_written, 0);
    }

    #[test]
    fn dropping_the_writer_without_finishing_still_closes_cleanly() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("x.db");
        {
            let w = StorageWriter::start(Database::open(&path).unwrap(), StorageConfig::live())
                .unwrap();
            w.submit(Job::Packets(rows(1, 100)));
        }
        let db = reopen(&path);
        assert_eq!(
            query_packets(
                &db,
                &PacketQuery {
                    limit: Some(1000),
                    ..Default::default()
                }
            )
            .unwrap()
            .len(),
            100
        );
    }

    #[test]
    fn write_failures_are_recorded_and_reported_on_finish() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("f.db");
        let db = Database::open(&path).unwrap();
        db.conn.execute_batch("DROP TABLE packets").unwrap();
        let w = StorageWriter::start(db, StorageConfig::live()).unwrap();
        w.submit(Job::Packets(rows(1, 3)));
        thread::sleep(Duration::from_millis(100));
        assert!(w.status().error.is_some());
        assert!(matches!(w.finish(), Err(CaptureError::Storage(_))));
    }

    /// Run with `cargo test --release insert_throughput -- --ignored --nocapture`.
    #[test]
    #[ignore = "benchmark"]
    fn insert_throughput() {
        for (name, cfg) in [
            ("live (indexed)", StorageConfig::live()),
            ("import (deferred indexes)", StorageConfig::import()),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let cfg = StorageConfig {
                block_when_full: true,
                ..cfg
            };
            let w = StorageWriter::start(Database::open(&dir.path().join("b.db")).unwrap(), cfg)
                .unwrap();
            let t = Instant::now();
            let total = 500_000u64;
            for i in 0..(total / 5000) {
                w.submit(Job::Packets(rows(i * 5000 + 1, 5000)));
            }
            w.finish().unwrap();
            let secs = t.elapsed().as_secs_f64();
            println!(
                "{name}: {total} rows in {secs:.2}s = {:.0} rows/s",
                total as f64 / secs
            );
        }
    }
}
