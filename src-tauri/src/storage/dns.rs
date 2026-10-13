//! DNS transactions.

use rusqlite::{Row, Transaction, params, params_from_iter};

use super::database::Database;
use crate::analytics::dns::{DnsAnswer, DnsStatus, DnsTransactionView};
use crate::capture::CaptureError;

fn status_name(s: DnsStatus) -> String {
    serde_json::to_value(s)
        .ok()
        .and_then(|v| v.as_str().map(str::to_string))
        .unwrap_or_default()
}

pub fn upsert_dns(
    tx: &Transaction<'_>,
    txns: &[DnsTransactionView],
) -> Result<usize, CaptureError> {
    let mut stmt = tx.prepare_cached(
        "INSERT INTO dns (id, flow_id, client, resolver, txid, qname, qtype, query_ts, resp_ts, latency, rcode, status, answers)
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)
         ON CONFLICT(id) DO UPDATE SET resp_ts=excluded.resp_ts, latency=excluded.latency, rcode=excluded.rcode, status=excluded.status, answers=excluded.answers",
    )?;
    for t in txns {
        stmt.execute(params![
            t.id as i64,
            t.flow_id.map(|v| v as i64),
            t.client.to_string(),
            t.resolver.to_string(),
            t.transaction_id,
            t.query_name.to_ascii_lowercase(),
            t.query_type,
            t.query_at,
            t.response_at,
            t.latency,
            t.response_code,
            status_name(t.status),
            serde_json::to_string(&t.answers).unwrap_or_else(|_| "[]".into())
        ])?;
    }
    Ok(txns.len())
}

fn from_row(r: &Row<'_>) -> rusqlite::Result<DnsTransactionView> {
    let ip = |s: String| {
        s.parse().map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(e))
        })
    };
    let status: String = r.get(11)?;
    let answers: String = r.get(12)?;
    Ok(DnsTransactionView {
        id: r.get::<_, i64>(0)? as u64,
        flow_id: r.get::<_, Option<i64>>(1)?.map(|v| v as u64),
        client: ip(r.get(2)?)?,
        resolver: ip(r.get(3)?)?,
        transaction_id: r.get(4)?,
        query_name: r.get(5)?,
        query_type: r.get(6)?,
        query_at: r.get(7)?,
        response_at: r.get(8)?,
        latency: r.get(9)?,
        response_code: r.get(10)?,
        status: serde_json::from_value(serde_json::Value::String(status))
            .unwrap_or(DnsStatus::Pending),
        answers: serde_json::from_str::<Vec<DnsAnswer>>(&answers).unwrap_or_default(),
    })
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct DnsQuery {
    /// Exact (case-insensitive) query name.
    pub name: Option<String>,
    pub ts_from: Option<i64>,
    pub ts_to: Option<i64>,
    pub limit: Option<u32>,
}

pub fn query_dns(db: &Database, q: &DnsQuery) -> Result<Vec<DnsTransactionView>, CaptureError> {
    let mut clauses: Vec<&str> = vec![];
    let mut args: Vec<rusqlite::types::Value> = vec![];
    if let Some(n) = &q.name {
        clauses.push("qname = ?");
        args.push(n.to_ascii_lowercase().into());
    }
    if let Some(v) = q.ts_from {
        clauses.push("query_ts >= ?");
        args.push(v.into());
    }
    if let Some(v) = q.ts_to {
        clauses.push("query_ts <= ?");
        args.push(v.into());
    }
    let w = if clauses.is_empty() {
        String::new()
    } else {
        format!(" WHERE {}", clauses.join(" AND "))
    };
    let sql = format!(
        "SELECT id, flow_id, client, resolver, txid, qname, qtype, query_ts, resp_ts, latency, rcode, status, answers FROM dns{w} ORDER BY id LIMIT {}",
        q.limit.unwrap_or(10_000).clamp(1, 200_000)
    );
    let mut stmt = db.conn.prepare(&sql)?;
    let rows = stmt.query_map(params_from_iter(args.iter()), from_row)?;
    Ok(rows.collect::<Result<Vec<_>, _>>()?)
}

pub fn dns_count(db: &Database) -> Result<u64, CaptureError> {
    db.count("dns")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn txn(id: u64, name: &str, status: DnsStatus, latency: Option<i64>) -> DnsTransactionView {
        DnsTransactionView {
            id,
            flow_id: Some(1),
            client: "192.168.1.20".parse().unwrap(),
            resolver: "8.8.8.8".parse().unwrap(),
            transaction_id: 7,
            query_name: name.into(),
            query_type: "A".into(),
            query_at: Some(id as i64 * 1000),
            response_at: latency.map(|l| id as i64 * 1000 + l),
            latency,
            response_code: latency.map(|_| "NOERROR".to_string()),
            status,
            answers: vec![DnsAnswer {
                name: name.into(),
                record_type: "A".into(),
                data: "140.82.121.5".into(),
                ttl: 60,
            }],
        }
    }

    #[test]
    fn transactions_round_trip_and_update_when_the_response_arrives() {
        let mut db = Database::in_memory().unwrap();
        let tx = db.conn.transaction().unwrap();
        let mut pending = txn(1, "api.github.com", DnsStatus::Pending, None);
        pending.answers.clear();
        upsert_dns(&tx, &[pending]).unwrap();
        tx.commit().unwrap();
        assert_eq!(
            query_dns(&db, &DnsQuery::default()).unwrap()[0].status,
            DnsStatus::Pending
        );

        let tx = db.conn.transaction().unwrap();
        let done = txn(1, "api.github.com", DnsStatus::Ok, Some(21_000));
        upsert_dns(&tx, std::slice::from_ref(&done)).unwrap();
        tx.commit().unwrap();
        assert_eq!(dns_count(&db).unwrap(), 1);
        assert_eq!(query_dns(&db, &DnsQuery::default()).unwrap(), vec![done]);
    }

    #[test]
    fn filters_by_name_and_time() {
        let mut db = Database::in_memory().unwrap();
        let tx = db.conn.transaction().unwrap();
        upsert_dns(
            &tx,
            &(1..=10)
                .map(|i| {
                    txn(
                        i,
                        if i % 2 == 0 {
                            "Api.Example.com"
                        } else {
                            "other.example"
                        },
                        DnsStatus::Ok,
                        Some(5),
                    )
                })
                .collect::<Vec<_>>(),
        )
        .unwrap();
        tx.commit().unwrap();
        let ids = |q: DnsQuery| {
            query_dns(&db, &q)
                .unwrap()
                .iter()
                .map(|t| t.id)
                .collect::<Vec<_>>()
        };
        assert_eq!(
            ids(DnsQuery {
                name: Some("API.example.com".into()),
                limit: Some(3),
                ..Default::default()
            }),
            vec![2, 4, 6]
        );
        assert_eq!(
            ids(DnsQuery {
                ts_from: Some(8000),
                ..Default::default()
            }),
            vec![8, 9, 10]
        );
    }
}
