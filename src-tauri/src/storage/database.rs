//! SQLite connection management: pragmas, schema, versioned migrations, size accounting.
//!
//! A capture database holds *derived* records (packet summaries, flows, DNS, events) — never raw
//! packet bytes — so even very large captures stay compact and queryable.

use std::path::{Path, PathBuf};

use rusqlite::Connection;

use crate::capture::CaptureError;

pub const SCHEMA_VERSION: i32 = 1;

impl From<rusqlite::Error> for CaptureError {
    fn from(e: rusqlite::Error) -> Self {
        CaptureError::Storage(e.to_string())
    }
}

const TABLES: &str = "
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL) WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS packets (
    id        INTEGER PRIMARY KEY,
    ts        INTEGER NOT NULL,
    flow_id   INTEGER,
    src_ip    TEXT,
    dst_ip    TEXT,
    src_port  INTEGER,
    dst_port  INTEGER,
    net       TEXT NOT NULL,
    transport TEXT,
    app       TEXT,
    length    INTEGER NOT NULL,
    orig_len  INTEGER NOT NULL,
    ttl       INTEGER,
    flags     TEXT,
    src_mac   TEXT,
    dst_mac   TEXT,
    info      TEXT NOT NULL,
    domain    TEXT,
    latency   INTEGER,
    payload   INTEGER NOT NULL,
    issues    TEXT
);

CREATE TABLE IF NOT EXISTS flows (
    id          INTEGER PRIMARY KEY,
    proto       TEXT NOT NULL,
    app         TEXT,
    a_ip        TEXT NOT NULL,
    a_port      INTEGER NOT NULL,
    b_ip        TEXT NOT NULL,
    b_port      INTEGER NOT NULL,
    started     INTEGER NOT NULL,
    last_seen   INTEGER NOT NULL,
    pkts_ab     INTEGER NOT NULL,
    pkts_ba     INTEGER NOT NULL,
    bytes_ab    INTEGER NOT NULL,
    bytes_ba    INTEGER NOT NULL,
    tcp_state   TEXT,
    retx        INTEGER NOT NULL,
    resets      INTEGER NOT NULL,
    dup_acks    INTEGER NOT NULL,
    zero_win    INTEGER NOT NULL,
    latency     INTEGER,
    domain      TEXT,
    domains     TEXT,
    tls         TEXT
);

CREATE TABLE IF NOT EXISTS events (
    id      INTEGER PRIMARY KEY,
    ts      INTEGER NOT NULL,
    kind    TEXT NOT NULL,
    flow_id INTEGER,
    host    TEXT,
    domain  TEXT,
    title   TEXT NOT NULL,
    detail  TEXT
);

CREATE TABLE IF NOT EXISTS dns (
    id        INTEGER PRIMARY KEY,
    flow_id   INTEGER,
    client    TEXT NOT NULL,
    resolver  TEXT NOT NULL,
    txid      INTEGER NOT NULL,
    qname     TEXT NOT NULL,
    qtype     TEXT NOT NULL,
    query_ts  INTEGER,
    resp_ts   INTEGER,
    latency   INTEGER,
    rcode     TEXT,
    status    TEXT NOT NULL,
    answers   TEXT NOT NULL
);
";

/// (name, SQL). Created after bulk loads, or immediately for incremental use.
pub const INDEXES: &[(&str, &str)] = &[
    (
        "idx_packets_ts",
        "CREATE INDEX IF NOT EXISTS idx_packets_ts ON packets(ts)",
    ),
    (
        "idx_packets_src",
        "CREATE INDEX IF NOT EXISTS idx_packets_src ON packets(src_ip)",
    ),
    (
        "idx_packets_dst",
        "CREATE INDEX IF NOT EXISTS idx_packets_dst ON packets(dst_ip)",
    ),
    (
        "idx_packets_app",
        "CREATE INDEX IF NOT EXISTS idx_packets_app ON packets(app) WHERE app IS NOT NULL",
    ),
    (
        "idx_packets_transport",
        "CREATE INDEX IF NOT EXISTS idx_packets_transport ON packets(transport) WHERE transport IS NOT NULL",
    ),
    (
        "idx_packets_flow",
        "CREATE INDEX IF NOT EXISTS idx_packets_flow ON packets(flow_id) WHERE flow_id IS NOT NULL",
    ),
    (
        "idx_packets_domain",
        "CREATE INDEX IF NOT EXISTS idx_packets_domain ON packets(domain) WHERE domain IS NOT NULL",
    ),
    (
        "idx_flows_a",
        "CREATE INDEX IF NOT EXISTS idx_flows_a ON flows(a_ip)",
    ),
    (
        "idx_flows_b",
        "CREATE INDEX IF NOT EXISTS idx_flows_b ON flows(b_ip)",
    ),
    (
        "idx_flows_last",
        "CREATE INDEX IF NOT EXISTS idx_flows_last ON flows(last_seen)",
    ),
    (
        "idx_flows_domain",
        "CREATE INDEX IF NOT EXISTS idx_flows_domain ON flows(domain) WHERE domain IS NOT NULL",
    ),
    (
        "idx_events_ts",
        "CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts)",
    ),
    (
        "idx_events_flow",
        "CREATE INDEX IF NOT EXISTS idx_events_flow ON events(flow_id) WHERE flow_id IS NOT NULL",
    ),
    (
        "idx_events_kind",
        "CREATE INDEX IF NOT EXISTS idx_events_kind ON events(kind)",
    ),
    (
        "idx_dns_qname",
        "CREATE INDEX IF NOT EXISTS idx_dns_qname ON dns(qname)",
    ),
    (
        "idx_dns_ts",
        "CREATE INDEX IF NOT EXISTS idx_dns_ts ON dns(query_ts)",
    ),
];

pub struct Database {
    pub(crate) conn: Connection,
    path: Option<PathBuf>,
}

impl Database {
    /// Opens (creating if needed) the database file and brings the schema up to date.
    pub fn open(path: &Path) -> Result<Self, CaptureError> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let conn = Connection::open(path)?;
        let mut db = Self {
            conn,
            path: Some(path.to_path_buf()),
        };
        db.configure(true)?;
        db.migrate()?;
        Ok(db)
    }

    pub fn in_memory() -> Result<Self, CaptureError> {
        let conn = Connection::open_in_memory()?;
        let mut db = Self { conn, path: None };
        db.configure(false)?;
        db.migrate()?;
        Ok(db)
    }

    fn configure(&mut self, on_disk: bool) -> Result<(), CaptureError> {
        // WAL + NORMAL: durable enough for a capture log, and commits don't fsync every time.
        if on_disk {
            self.conn.pragma_update(None, "journal_mode", "WAL")?;
        }
        self.conn.pragma_update(None, "synchronous", "NORMAL")?;
        self.conn.pragma_update(None, "temp_store", "MEMORY")?;
        self.conn.pragma_update(None, "cache_size", -65_536)?; // 64 MiB
        self.conn.pragma_update(None, "foreign_keys", "OFF")?;
        Ok(())
    }

    fn migrate(&mut self) -> Result<(), CaptureError> {
        let version: i32 = self
            .conn
            .pragma_query_value(None, "user_version", |r| r.get(0))?;
        if version > SCHEMA_VERSION {
            return Err(CaptureError::Storage(format!(
                "this database was written by a newer version of B&M Packet (schema {version})"
            )));
        }
        if version < 1 {
            self.conn.execute_batch(TABLES)?;
            self.create_indexes()?;
            self.conn
                .pragma_update(None, "user_version", SCHEMA_VERSION)?;
        }
        Ok(())
    }

    pub fn create_indexes(&self) -> Result<(), CaptureError> {
        for (_, sql) in INDEXES {
            self.conn.execute_batch(sql)?;
        }
        Ok(())
    }

    /// Drops the secondary indexes so a large load doesn't pay for them row by row.
    /// Call [`Database::create_indexes`] afterwards.
    pub fn drop_indexes(&self) -> Result<(), CaptureError> {
        for (name, _) in INDEXES {
            self.conn
                .execute_batch(&format!("DROP INDEX IF EXISTS {name}"))?;
        }
        Ok(())
    }

    pub fn index_names(&self) -> Result<Vec<String>, CaptureError> {
        let mut stmt = self.conn.prepare("SELECT name FROM sqlite_master WHERE type = 'index' AND name LIKE 'idx_%' ORDER BY name")?;
        let names = stmt
            .query_map([], |r| r.get::<_, String>(0))?
            .collect::<Result<Vec<_>, _>>()?;
        Ok(names)
    }

    pub fn set_meta(&self, key: &str, value: &str) -> Result<(), CaptureError> {
        self.conn.execute("INSERT INTO meta(key, value) VALUES (?1, ?2) ON CONFLICT(key) DO UPDATE SET value = excluded.value", [key, value])?;
        Ok(())
    }

    pub fn meta(&self, key: &str) -> Result<Option<String>, CaptureError> {
        match self
            .conn
            .query_row("SELECT value FROM meta WHERE key = ?1", [key], |r| r.get(0))
        {
            Ok(v) => Ok(Some(v)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Logical size of the database (excluding the WAL), in bytes.
    pub fn size_bytes(&self) -> Result<u64, CaptureError> {
        let pages: i64 = self
            .conn
            .pragma_query_value(None, "page_count", |r| r.get(0))?;
        let size: i64 = self
            .conn
            .pragma_query_value(None, "page_size", |r| r.get(0))?;
        Ok(u64::try_from(pages * size).unwrap_or(0))
    }

    /// Folds the WAL back into the main file (e.g. when a capture ends).
    pub fn checkpoint(&self) -> Result<(), CaptureError> {
        self.conn
            .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |_| Ok(()))?;
        Ok(())
    }

    pub fn path(&self) -> Option<&Path> {
        self.path.as_deref()
    }

    pub(crate) fn count(&self, table: &str) -> Result<u64, CaptureError> {
        // `table` only ever comes from this crate's own constants.
        let n: i64 = self
            .conn
            .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |r| r.get(0))?;
        Ok(u64::try_from(n).unwrap_or(0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn creates_schema_and_all_indexes() {
        let db = Database::in_memory().unwrap();
        assert_eq!(db.index_names().unwrap().len(), INDEXES.len());
        let v: i32 = db
            .conn
            .pragma_query_value(None, "user_version", |r| r.get(0))
            .unwrap();
        assert_eq!(v, SCHEMA_VERSION);
    }

    #[test]
    fn opening_twice_is_idempotent_and_keeps_data() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("a/b/c.db");
        {
            let db = Database::open(&path).unwrap();
            db.set_meta("source", "eth0").unwrap();
        }
        let db = Database::open(&path).unwrap();
        assert_eq!(db.meta("source").unwrap().as_deref(), Some("eth0"));
        assert_eq!(db.meta("missing").unwrap(), None);
        assert_eq!(db.path(), Some(path.as_path()));
    }

    #[test]
    fn refuses_databases_from_the_future() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("f.db");
        Database::open(&path)
            .unwrap()
            .conn
            .pragma_update(None, "user_version", SCHEMA_VERSION + 5)
            .unwrap();
        assert!(
            matches!(Database::open(&path), Err(CaptureError::Storage(m)) if m.contains("newer version"))
        );
    }

    #[test]
    fn rejects_files_that_are_not_databases() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("junk.db");
        std::fs::write(&path, vec![0xAB; 4096]).unwrap();
        assert!(matches!(
            Database::open(&path),
            Err(CaptureError::Storage(_))
        ));
    }

    #[test]
    fn indexes_can_be_dropped_and_rebuilt() {
        let db = Database::in_memory().unwrap();
        db.drop_indexes().unwrap();
        assert!(db.index_names().unwrap().is_empty());
        db.create_indexes().unwrap();
        assert_eq!(db.index_names().unwrap().len(), INDEXES.len());
    }

    #[test]
    fn size_and_checkpoint_work_on_disk() {
        let dir = tempfile::tempdir().unwrap();
        let db = Database::open(&dir.path().join("s.db")).unwrap();
        assert!(db.size_bytes().unwrap() > 0);
        db.checkpoint().unwrap();
        assert_eq!(db.count("packets").unwrap(), 0);
    }
}
