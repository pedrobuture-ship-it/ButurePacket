//! Flow rows: upserted as the flow engine reports changes, queried by address or domain.

use rusqlite::{Row, Transaction, params};

use super::database::Database;
use crate::capture::CaptureError;
use crate::flows::{Endpoint, FlowView};

const COLUMNS: &str = "id, proto, app, a_ip, a_port, b_ip, b_port, started, last_seen, pkts_ab, pkts_ba, bytes_ab, bytes_ba, tcp_state, retx, resets, dup_acks, zero_win, latency, domain, domains, tls";

fn json<T: serde::Serialize>(v: &T) -> Option<String> {
    serde_json::to_string(v).ok()
}

pub fn upsert_flows(tx: &Transaction<'_>, flows: &[FlowView]) -> Result<usize, CaptureError> {
    let mut stmt = tx.prepare_cached(&format!(
        "INSERT INTO flows ({COLUMNS}) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?20,?21,?22)
         ON CONFLICT(id) DO UPDATE SET app=excluded.app, last_seen=excluded.last_seen, pkts_ab=excluded.pkts_ab, pkts_ba=excluded.pkts_ba,
           bytes_ab=excluded.bytes_ab, bytes_ba=excluded.bytes_ba, tcp_state=excluded.tcp_state, retx=excluded.retx, resets=excluded.resets,
           dup_acks=excluded.dup_acks, zero_win=excluded.zero_win, latency=excluded.latency, domain=excluded.domain,
           domains=excluded.domains, tls=excluded.tls"
    ))?;
    for f in flows {
        let state = f
            .tcp_state
            .as_ref()
            .and_then(|s| serde_json::to_value(s).ok())
            .and_then(|v| v.as_str().map(str::to_string));
        let domain = f
            .tls
            .as_ref()
            .and_then(|t| t.sni.clone())
            .or_else(|| f.domains.first().cloned())
            .map(|d| d.to_ascii_lowercase());
        stmt.execute(params![
            f.id as i64,
            f.protocol,
            f.application_protocol,
            f.endpoint_a.ip.to_string(),
            f.endpoint_a.port,
            f.endpoint_b.ip.to_string(),
            f.endpoint_b.port,
            f.started_at,
            f.last_seen_at,
            f.packets_a_to_b as i64,
            f.packets_b_to_a as i64,
            f.bytes_a_to_b as i64,
            f.bytes_b_to_a as i64,
            state,
            f.retransmissions as i64,
            f.resets as i64,
            f.duplicate_acks as i64,
            f.zero_windows as i64,
            f.latency,
            domain,
            (!f.domains.is_empty()).then(|| json(&f.domains)).flatten(),
            f.tls.as_ref().and_then(json)
        ])?;
    }
    Ok(flows.len())
}

fn from_row(r: &Row<'_>) -> rusqlite::Result<FlowView> {
    let ip = |s: String| {
        s.parse().map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(e))
        })
    };
    let (pab, pba, bab, bba): (i64, i64, i64, i64) =
        (r.get(9)?, r.get(10)?, r.get(11)?, r.get(12)?);
    let started: i64 = r.get(7)?;
    let last: i64 = r.get(8)?;
    let state: Option<String> = r.get(13)?;
    let domains: Option<String> = r.get(20)?;
    let tls: Option<String> = r.get(21)?;
    Ok(FlowView {
        id: r.get::<_, i64>(0)? as u64,
        protocol: r.get(1)?,
        application_protocol: r.get(2)?,
        endpoint_a: Endpoint {
            ip: ip(r.get(3)?)?,
            port: r.get(4)?,
        },
        endpoint_b: Endpoint {
            ip: ip(r.get(5)?)?,
            port: r.get(6)?,
        },
        started_at: started,
        last_seen_at: last,
        duration: last - started,
        packets_a_to_b: pab as u64,
        packets_b_to_a: pba as u64,
        bytes_a_to_b: bab as u64,
        bytes_b_to_a: bba as u64,
        total_packets: (pab + pba) as u64,
        total_bytes: (bab + bba) as u64,
        tcp_state: state.and_then(|s| serde_json::from_value(serde_json::Value::String(s)).ok()),
        retransmissions: r.get::<_, i64>(14)? as u64,
        resets: r.get::<_, i64>(15)? as u64,
        duplicate_acks: r.get::<_, i64>(16)? as u64,
        zero_windows: r.get::<_, i64>(17)? as u64,
        latency: r.get(18)?,
        domains: domains
            .and_then(|d| serde_json::from_str(&d).ok())
            .unwrap_or_default(),
        process: None,
        tls: tls.and_then(|t| serde_json::from_str(&t).ok()),
        // Sparklines are live-only and not persisted.
        sparkline: Vec::new(),
    })
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct FlowQuery {
    pub ip: Option<String>,
    pub domain: Option<String>,
    pub limit: Option<u32>,
}

/// Flows ordered by traffic, busiest first.
pub fn query_flows(db: &Database, q: &FlowQuery) -> Result<Vec<FlowView>, CaptureError> {
    let mut sql = format!("SELECT {COLUMNS} FROM flows");
    let mut args: Vec<String> = vec![];
    let mut clauses = vec![];
    if let Some(ip) = &q.ip {
        clauses.push("(a_ip = ? OR b_ip = ?)");
        args.extend([ip.clone(), ip.clone()]);
    }
    if let Some(d) = &q.domain {
        clauses.push("domain = ?");
        args.push(d.to_ascii_lowercase());
    }
    if !clauses.is_empty() {
        sql.push_str(&format!(" WHERE {}", clauses.join(" AND ")));
    }
    sql.push_str(&format!(
        " ORDER BY (bytes_ab + bytes_ba) DESC, id LIMIT {}",
        q.limit.unwrap_or(1000).clamp(1, 100_000)
    ));
    let mut stmt = db.conn.prepare(&sql)?;
    let rows = stmt.query_map(rusqlite::params_from_iter(args.iter()), from_row)?;
    Ok(rows.collect::<Result<Vec<_>, _>>()?)
}

pub fn flow_count(db: &Database) -> Result<u64, CaptureError> {
    db.count("flows")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analytics::tls::TlsInfo;
    use crate::flows::TcpState;

    fn flow(id: u64, a: &str, b: &str, bytes: u64) -> FlowView {
        FlowView {
            id,
            protocol: "TCP".into(),
            application_protocol: Some("TLS".into()),
            endpoint_a: Endpoint {
                ip: a.parse().unwrap(),
                port: 50000 + id as u16,
            },
            endpoint_b: Endpoint {
                ip: b.parse().unwrap(),
                port: 443,
            },
            started_at: 1_000_000,
            last_seen_at: 9_000_000,
            duration: 8_000_000,
            packets_a_to_b: 10,
            packets_b_to_a: 20,
            bytes_a_to_b: bytes / 10,
            bytes_b_to_a: bytes - bytes / 10,
            total_packets: 30,
            total_bytes: bytes,
            tcp_state: Some(TcpState::Established),
            retransmissions: 3,
            resets: 0,
            duplicate_acks: 1,
            zero_windows: 0,
            latency: Some(21_000),
            domains: vec!["api.github.com".into()],
            process: None,
            tls: Some(TlsInfo {
                version: Some("TLS 1.3".into()),
                sni: Some("GitHub.com".into()),
                alpn_offered: vec!["h2".into()],
                ..Default::default()
            }),
            sparkline: Vec::new(),
        }
    }

    fn insert(db: &mut Database, flows: &[FlowView]) {
        let tx = db.conn.transaction().unwrap();
        upsert_flows(&tx, flows).unwrap();
        tx.commit().unwrap();
    }

    #[test]
    fn flows_round_trip() {
        let mut db = Database::in_memory().unwrap();
        let f = flow(1, "192.168.1.20", "140.82.121.4", 10_000);
        insert(&mut db, std::slice::from_ref(&f));
        let back = query_flows(&db, &FlowQuery::default()).unwrap();
        assert_eq!(back, vec![f]);
    }

    #[test]
    fn upsert_updates_counters_in_place() {
        let mut db = Database::in_memory().unwrap();
        insert(&mut db, &[flow(1, "10.0.0.1", "10.0.0.2", 100)]);
        let mut grown = flow(1, "10.0.0.1", "10.0.0.2", 5000);
        grown.last_seen_at = 20_000_000;
        grown.tcp_state = Some(TcpState::Closed);
        insert(&mut db, &[grown]);
        assert_eq!(flow_count(&db).unwrap(), 1);
        let f = &query_flows(&db, &FlowQuery::default()).unwrap()[0];
        assert_eq!(
            (f.total_bytes, f.last_seen_at, f.tcp_state),
            (5000, 20_000_000, Some(TcpState::Closed))
        );
        assert_eq!(f.started_at, 1_000_000); // identity fields never change
    }

    #[test]
    fn queries_by_address_and_domain_ordered_by_traffic() {
        let mut db = Database::in_memory().unwrap();
        let mut plain = flow(3, "10.0.0.1", "9.9.9.9", 50);
        plain.tls = None;
        plain.domains = vec![];
        insert(
            &mut db,
            &[
                flow(1, "10.0.0.1", "1.1.1.1", 100),
                flow(2, "10.0.0.2", "1.1.1.1", 900),
                plain,
            ],
        );
        let ids = |q: FlowQuery| {
            query_flows(&db, &q)
                .unwrap()
                .iter()
                .map(|f| f.id)
                .collect::<Vec<_>>()
        };
        assert_eq!(ids(FlowQuery::default()), vec![2, 1, 3]);
        assert_eq!(
            ids(FlowQuery {
                ip: Some("10.0.0.1".into()),
                ..Default::default()
            }),
            vec![1, 3]
        );
        assert_eq!(
            ids(FlowQuery {
                ip: Some("1.1.1.1".into()),
                ..Default::default()
            }),
            vec![2, 1]
        );
        assert_eq!(
            ids(FlowQuery {
                domain: Some("GITHUB.com".into()),
                ..Default::default()
            }),
            vec![2, 1]
        );
        assert_eq!(
            ids(FlowQuery {
                limit: Some(1),
                ..Default::default()
            }),
            vec![2]
        );
        assert!(
            ids(FlowQuery {
                domain: Some("nope".into()),
                ..Default::default()
            })
            .is_empty()
        );
    }

    #[test]
    fn ipv6_endpoints_survive() {
        let mut db = Database::in_memory().unwrap();
        insert(&mut db, &[flow(1, "fe80::1", "2606:4700::1111", 10)]);
        let f = &query_flows(&db, &FlowQuery::default()).unwrap()[0];
        assert_eq!(f.endpoint_b.ip.to_string(), "2606:4700::1111");
    }
}
