//! Packet summary rows: batched inserts and indexed queries.

use rusqlite::{Row, ToSql, Transaction, params, params_from_iter};
use serde::Deserialize;

use super::database::Database;
use crate::capture::CaptureError;
use crate::protocols::PacketSummary;

const COLUMNS: &str = "id, ts, flow_id, src_ip, dst_ip, src_port, dst_port, net, transport, app, length, orig_len, ttl, flags, src_mac, dst_mac, info, domain, latency, payload, issues";
pub const MAX_PAGE: u32 = 10_000;
pub const DEFAULT_PAGE: u32 = 1_000;

fn lower(s: &str) -> String {
    s.to_ascii_lowercase()
}

/// Display casing for protocol labels that are stored lower-cased (so they can be indexed and
/// matched without case folding).
fn restore_case(l: &str) -> String {
    match l {
        "ipv4" => "IPv4".into(),
        "ipv6" => "IPv6".into(),
        "icmpv6" => "ICMPv6".into(),
        _ if l.starts_with("unknown") => format!("Unknown{}", &l["unknown".len()..]),
        _ if l.starts_with("ip proto") => format!("IP proto{}", &l["ip proto".len()..]),
        _ => l.to_ascii_uppercase(),
    }
}

fn flag_name(s: &str) -> Option<&'static str> {
    ["SYN", "FIN", "RST", "PSH", "ACK", "URG", "ECE", "CWR"]
        .into_iter()
        .find(|f| *f == s)
}

/// Inserts a batch inside the caller's transaction using one cached statement.
pub fn insert_packets(tx: &Transaction<'_>, rows: &[PacketSummary]) -> Result<usize, CaptureError> {
    let mut stmt = tx.prepare_cached(&format!("INSERT OR REPLACE INTO packets ({COLUMNS}) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?20,?21)"))?;
    for p in rows {
        let flags = p.tcp_flags.as_ref().map(|f| f.join(","));
        let issues = (!p.issues.is_empty()).then(|| p.issues.join("\n"));
        stmt.execute(params![
            p.id as i64,
            p.timestamp,
            p.flow_id.map(|v| v as i64),
            p.source_ip,
            p.destination_ip,
            p.source_port,
            p.destination_port,
            lower(&p.network_protocol),
            p.transport_protocol.as_deref().map(lower),
            p.application_protocol.as_deref().map(lower),
            p.captured_length,
            p.original_length,
            p.ttl,
            flags,
            p.source_mac,
            p.destination_mac,
            p.info,
            p.domain.as_deref().map(lower),
            p.latency,
            p.payload_length,
            issues
        ])?;
    }
    Ok(rows.len())
}

fn from_row(r: &Row<'_>) -> rusqlite::Result<PacketSummary> {
    let flags: Option<String> = r.get(13)?;
    let issues: Option<String> = r.get(20)?;
    Ok(PacketSummary {
        id: r.get::<_, i64>(0)? as u64,
        timestamp: r.get(1)?,
        flow_id: r.get::<_, Option<i64>>(2)?.map(|v| v as u64),
        source_ip: r.get(3)?,
        destination_ip: r.get(4)?,
        source_port: r.get(5)?,
        destination_port: r.get(6)?,
        network_protocol: restore_case(&r.get::<_, String>(7)?),
        transport_protocol: r.get::<_, Option<String>>(8)?.map(|s| restore_case(&s)),
        application_protocol: r.get::<_, Option<String>>(9)?.map(|s| restore_case(&s)),
        captured_length: r.get(10)?,
        original_length: r.get(11)?,
        ttl: r.get(12)?,
        tcp_flags: flags.map(|f| f.split(',').filter_map(flag_name).collect()),
        source_mac: r.get(14)?,
        destination_mac: r.get(15)?,
        info: r.get(16)?,
        domain: r.get(17)?,
        latency: r.get(18)?,
        payload_length: r.get(19)?,
        issues: issues
            .map(|s| s.split('\n').map(str::to_string).collect())
            .unwrap_or_default(),
    })
}

/// Everything here maps to an indexed column, so queries stay fast on millions of rows.
#[derive(Debug, Default, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", default)]
pub struct PacketQuery {
    pub ts_from: Option<i64>,
    pub ts_to: Option<i64>,
    /// Either endpoint.
    pub ip: Option<String>,
    pub src_ip: Option<String>,
    pub dst_ip: Option<String>,
    /// Matches network, transport or application protocol (case-insensitive).
    pub protocol: Option<String>,
    pub flow_id: Option<u64>,
    /// Exact domain (case-insensitive).
    pub domain: Option<String>,
    /// Keyset paging: only rows after this id (before it when descending).
    pub after_id: Option<u64>,
    pub limit: Option<u32>,
    pub descending: bool,
}

impl PacketQuery {
    fn where_clause(&self) -> (String, Vec<Box<dyn ToSql>>) {
        let mut clauses: Vec<String> = Vec::new();
        let mut args: Vec<Box<dyn ToSql>> = Vec::new();
        let mut add = |sql: &str, vals: Vec<Box<dyn ToSql>>| {
            clauses.push(sql.to_string());
            args.extend(vals);
        };
        if let Some(v) = self.ts_from {
            add("ts >= ?", vec![Box::new(v)]);
        }
        if let Some(v) = self.ts_to {
            add("ts <= ?", vec![Box::new(v)]);
        }
        if let Some(v) = &self.ip {
            add(
                "(src_ip = ? OR dst_ip = ?)",
                vec![Box::new(v.clone()), Box::new(v.clone())],
            );
        }
        if let Some(v) = &self.src_ip {
            add("src_ip = ?", vec![Box::new(v.clone())]);
        }
        if let Some(v) = &self.dst_ip {
            add("dst_ip = ?", vec![Box::new(v.clone())]);
        }
        if let Some(v) = &self.protocol {
            let l = lower(v);
            add(
                "(app = ? OR transport = ? OR net = ?)",
                vec![Box::new(l.clone()), Box::new(l.clone()), Box::new(l)],
            );
        }
        if let Some(v) = self.flow_id {
            add("flow_id = ?", vec![Box::new(v as i64)]);
        }
        if let Some(v) = &self.domain {
            add("domain = ?", vec![Box::new(lower(v))]);
        }
        if let Some(v) = self.after_id {
            add(
                if self.descending { "id < ?" } else { "id > ?" },
                vec![Box::new(v as i64)],
            );
        }
        let sql = if clauses.is_empty() {
            String::new()
        } else {
            format!(" WHERE {}", clauses.join(" AND "))
        };
        (sql, args)
    }

    fn limit(&self) -> u32 {
        self.limit.unwrap_or(DEFAULT_PAGE).clamp(1, MAX_PAGE)
    }

    pub fn select_sql(&self) -> (String, Vec<Box<dyn ToSql>>) {
        let (w, args) = self.where_clause();
        let order = if self.descending { "DESC" } else { "ASC" };
        (
            format!(
                "SELECT {COLUMNS} FROM packets{w} ORDER BY id {order} LIMIT {}",
                self.limit()
            ),
            args,
        )
    }
}

pub fn query_packets(db: &Database, q: &PacketQuery) -> Result<Vec<PacketSummary>, CaptureError> {
    let (sql, args) = q.select_sql();
    let mut stmt = db.conn.prepare_cached(&sql)?;
    let rows = stmt.query_map(params_from_iter(args.iter().map(|a| a.as_ref())), from_row)?;
    Ok(rows.collect::<Result<Vec<_>, _>>()?)
}

/// Number of rows matching the filters (ignores paging).
pub fn count_packets(db: &Database, q: &PacketQuery) -> Result<u64, CaptureError> {
    let mut unpaged = q.clone();
    unpaged.after_id = None;
    let (w, args) = unpaged.where_clause();
    let n: i64 = db.conn.query_row(
        &format!("SELECT COUNT(*) FROM packets{w}"),
        params_from_iter(args.iter().map(|a| a.as_ref())),
        |r| r.get(0),
    )?;
    Ok(u64::try_from(n).unwrap_or(0))
}

pub fn packet_by_id(db: &Database, id: u64) -> Result<Option<PacketSummary>, CaptureError> {
    match db.conn.query_row(
        &format!("SELECT {COLUMNS} FROM packets WHERE id = ?1"),
        [id as i64],
        from_row,
    ) {
        Ok(p) => Ok(Some(p)),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
        Err(e) => Err(e.into()),
    }
}

pub fn packet_count(db: &Database) -> Result<u64, CaptureError> {
    db.count("packets")
}

#[cfg(test)]
pub(crate) fn sample(id: u64, src: &str, dst: &str, app: Option<&str>, ts: i64) -> PacketSummary {
    PacketSummary {
        id,
        flow_id: Some(id % 3),
        timestamp: ts,
        captured_length: 100,
        original_length: 100,
        source_mac: Some("aa:bb:cc:dd:ee:ff".into()),
        destination_mac: Some("11:22:33:44:55:66".into()),
        source_ip: Some(src.into()),
        destination_ip: Some(dst.into()),
        source_port: Some(50000),
        destination_port: Some(443),
        network_protocol: "IPv4".into(),
        transport_protocol: Some("TCP".into()),
        application_protocol: app.map(str::to_string),
        tcp_flags: Some(vec!["SYN", "ACK"]),
        ttl: Some(64),
        payload_length: 0,
        info: "x".into(),
        domain: None,
        latency: None,
        issues: vec![],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn db_with(rows: &[PacketSummary]) -> Database {
        let mut db = Database::in_memory().unwrap();
        let tx = db.conn.transaction().unwrap();
        insert_packets(&tx, rows).unwrap();
        tx.commit().unwrap();
        db
    }

    #[test]
    fn rows_round_trip_exactly() {
        let mut p = sample(
            7,
            "192.168.1.20",
            "140.82.121.4",
            Some("TLS"),
            1_700_000_000_123_456,
        );
        p.domain = Some("api.github.com".into());
        p.latency = Some(21_000);
        p.issues = vec!["Truncated TCP".into(), "Fragmented IP packet".into()];
        let mut arp = sample(8, "1.1.1.1", "2.2.2.2", None, 5);
        arp.network_protocol = "ARP".into();
        arp.transport_protocol = None;
        arp.tcp_flags = None;
        arp.source_port = None;
        arp.destination_port = None;
        let mut odd = sample(9, "1.1.1.1", "2.2.2.2", None, 6);
        odd.network_protocol = "Unknown (0x88cc)".into();
        odd.transport_protocol = Some("ICMPv6".into());
        let db = db_with(&[p.clone(), arp.clone(), odd.clone()]);
        assert_eq!(packet_by_id(&db, 7).unwrap().unwrap(), p);
        assert_eq!(packet_by_id(&db, 8).unwrap().unwrap(), arp);
        let back = packet_by_id(&db, 9).unwrap().unwrap();
        assert_eq!(back.network_protocol, "Unknown (0x88cc)");
        assert_eq!(back.transport_protocol.as_deref(), Some("ICMPv6"));
        assert!(packet_by_id(&db, 99).unwrap().is_none());
    }

    #[test]
    fn filters_use_the_indexed_columns() {
        let rows: Vec<_> = (1..=100)
            .map(|i| {
                let mut p = sample(
                    i,
                    if i % 2 == 0 { "10.0.0.1" } else { "10.0.0.2" },
                    "8.8.8.8",
                    if i % 10 == 0 {
                        Some("DNS")
                    } else {
                        Some("TLS")
                    },
                    i as i64 * 1000,
                );
                p.domain = (i % 4 == 0).then(|| "Api.Example.com".to_string());
                p
            })
            .collect();
        let db = db_with(&rows);
        let ids = |q: PacketQuery| {
            query_packets(&db, &q)
                .unwrap()
                .iter()
                .map(|p| p.id)
                .collect::<Vec<_>>()
        };
        assert_eq!(count_packets(&db, &PacketQuery::default()).unwrap(), 100);
        assert_eq!(
            count_packets(
                &db,
                &PacketQuery {
                    src_ip: Some("10.0.0.1".into()),
                    ..Default::default()
                }
            )
            .unwrap(),
            50
        );
        assert_eq!(
            ids(PacketQuery {
                ip: Some("10.0.0.1".into()),
                limit: Some(3),
                ..Default::default()
            }),
            vec![2, 4, 6]
        );
        assert_eq!(
            count_packets(
                &db,
                &PacketQuery {
                    dst_ip: Some("8.8.8.8".into()),
                    ..Default::default()
                }
            )
            .unwrap(),
            100
        );
        assert_eq!(
            count_packets(
                &db,
                &PacketQuery {
                    protocol: Some("dns".into()),
                    ..Default::default()
                }
            )
            .unwrap(),
            10
        );
        assert_eq!(
            count_packets(
                &db,
                &PacketQuery {
                    protocol: Some("TCP".into()),
                    ..Default::default()
                }
            )
            .unwrap(),
            100
        );
        assert_eq!(
            count_packets(
                &db,
                &PacketQuery {
                    protocol: Some("ipv4".into()),
                    ..Default::default()
                }
            )
            .unwrap(),
            100
        );
        assert_eq!(
            ids(PacketQuery {
                ts_from: Some(10_000),
                ts_to: Some(13_000),
                ..Default::default()
            }),
            vec![10, 11, 12, 13]
        );
        assert_eq!(
            ids(PacketQuery {
                domain: Some("api.example.COM".into()),
                limit: Some(2),
                ..Default::default()
            }),
            vec![4, 8]
        );
        assert_eq!(
            ids(PacketQuery {
                flow_id: Some(1),
                limit: Some(3),
                ..Default::default()
            }),
            vec![1, 4, 7]
        );
        assert_eq!(
            count_packets(
                &db,
                &PacketQuery {
                    ip: Some("10.0.0.2".into()),
                    protocol: Some("tls".into()),
                    ..Default::default()
                }
            )
            .unwrap(),
            50
        );
        assert!(
            ids(PacketQuery {
                ip: Some("203.0.113.9".into()),
                ..Default::default()
            })
            .is_empty()
        );
    }

    #[test]
    fn keyset_paging_walks_every_row_exactly_once_in_both_directions() {
        let db = db_with(
            &(1..=95)
                .map(|i| sample(i, "1.1.1.1", "2.2.2.2", None, i as i64))
                .collect::<Vec<_>>(),
        );
        for descending in [false, true] {
            let mut seen = vec![];
            let mut after = None;
            loop {
                let page = query_packets(
                    &db,
                    &PacketQuery {
                        after_id: after,
                        limit: Some(20),
                        descending,
                        ..Default::default()
                    },
                )
                .unwrap();
                if page.is_empty() {
                    break;
                }
                after = page.last().map(|p| p.id);
                seen.extend(page.iter().map(|p| p.id));
            }
            let mut expected: Vec<u64> = (1..=95).collect();
            if descending {
                expected.reverse();
            }
            assert_eq!(seen, expected);
        }
    }

    #[test]
    fn page_size_is_clamped() {
        assert_eq!(
            PacketQuery {
                limit: Some(0),
                ..Default::default()
            }
            .limit(),
            1
        );
        assert_eq!(
            PacketQuery {
                limit: Some(u32::MAX),
                ..Default::default()
            }
            .limit(),
            MAX_PAGE
        );
        assert_eq!(PacketQuery::default().limit(), DEFAULT_PAGE);
    }

    #[test]
    fn hostile_values_are_bound_not_interpolated() {
        let db = db_with(&[sample(1, "1.1.1.1", "2.2.2.2", Some("TLS"), 1)]);
        let evil = "x' OR '1'='1'; DROP TABLE packets; --";
        for q in [
            PacketQuery {
                ip: Some(evil.into()),
                ..Default::default()
            },
            PacketQuery {
                protocol: Some(evil.into()),
                ..Default::default()
            },
            PacketQuery {
                domain: Some(evil.into()),
                ..Default::default()
            },
        ] {
            assert_eq!(count_packets(&db, &q).unwrap(), 0);
        }
        assert_eq!(packet_count(&db).unwrap(), 1);
    }

    #[test]
    fn queries_are_served_by_indexes_not_table_scans() {
        let db = db_with(
            &(1..=10)
                .map(|i| sample(i, "1.1.1.1", "2.2.2.2", Some("TLS"), i as i64))
                .collect::<Vec<_>>(),
        );
        let plan = |q: PacketQuery| {
            let (sql, args) = q.select_sql();
            let mut stmt = db
                .conn
                .prepare(&format!("EXPLAIN QUERY PLAN {sql}"))
                .unwrap();
            let rows = stmt
                .query_map(params_from_iter(args.iter().map(|a| a.as_ref())), |r| {
                    r.get::<_, String>(3)
                })
                .unwrap();
            rows.collect::<Result<Vec<_>, _>>().unwrap().join(" | ")
        };
        for (q, index) in [
            (
                PacketQuery {
                    src_ip: Some("1.1.1.1".into()),
                    ..Default::default()
                },
                "idx_packets_src",
            ),
            (
                PacketQuery {
                    dst_ip: Some("2.2.2.2".into()),
                    ..Default::default()
                },
                "idx_packets_dst",
            ),
            (
                PacketQuery {
                    ts_from: Some(5),
                    ts_to: Some(7),
                    ..Default::default()
                },
                "idx_packets_ts",
            ),
            (
                PacketQuery {
                    flow_id: Some(1),
                    ..Default::default()
                },
                "idx_packets_flow",
            ),
            (
                PacketQuery {
                    domain: Some("a.com".into()),
                    ..Default::default()
                },
                "idx_packets_domain",
            ),
        ] {
            let p = plan(q.clone());
            assert!(p.contains(index), "{q:?} → {p}");
            assert!(!p.contains("SCAN packets"), "{q:?} scans: {p}");
        }
    }
}
