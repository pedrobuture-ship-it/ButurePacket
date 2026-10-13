//! Timeline events.

use rusqlite::{Row, Transaction, params, params_from_iter};

use super::database::Database;
use crate::analytics::events::{EventKind, TimelineEvent};
use crate::capture::CaptureError;

fn kind_name(k: EventKind) -> String {
    serde_json::to_value(k)
        .ok()
        .and_then(|v| v.as_str().map(str::to_string))
        .unwrap_or_default()
}

pub fn insert_events(
    tx: &Transaction<'_>,
    events: &[TimelineEvent],
) -> Result<usize, CaptureError> {
    let mut stmt = tx.prepare_cached("INSERT OR REPLACE INTO events (id, ts, kind, flow_id, host, domain, title, detail) VALUES (?1,?2,?3,?4,?5,?6,?7,?8)")?;
    for e in events {
        stmt.execute(params![
            e.id as i64,
            e.ts,
            kind_name(e.kind),
            e.flow_id.map(|v| v as i64),
            e.host,
            e.domain.as_deref().map(str::to_ascii_lowercase),
            e.title,
            e.detail
        ])?;
    }
    Ok(events.len())
}

fn from_row(r: &Row<'_>) -> rusqlite::Result<TimelineEvent> {
    let kind: String = r.get(2)?;
    Ok(TimelineEvent {
        id: r.get::<_, i64>(0)? as u64,
        ts: r.get(1)?,
        kind: serde_json::from_value(serde_json::Value::String(kind)).map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(2, rusqlite::types::Type::Text, Box::new(e))
        })?,
        flow_id: r.get::<_, Option<i64>>(3)?.map(|v| v as u64),
        host: r.get(4)?,
        domain: r.get(5)?,
        title: r.get(6)?,
        detail: r.get(7)?,
    })
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct EventQuery {
    pub ts_from: Option<i64>,
    pub ts_to: Option<i64>,
    pub flow_id: Option<u64>,
    pub kind: Option<EventKind>,
    pub limit: Option<u32>,
}

/// Events in time order.
pub fn query_events(db: &Database, q: &EventQuery) -> Result<Vec<TimelineEvent>, CaptureError> {
    let mut clauses: Vec<&str> = vec![];
    let mut args: Vec<rusqlite::types::Value> = vec![];
    if let Some(v) = q.ts_from {
        clauses.push("ts >= ?");
        args.push(v.into());
    }
    if let Some(v) = q.ts_to {
        clauses.push("ts <= ?");
        args.push(v.into());
    }
    if let Some(v) = q.flow_id {
        clauses.push("flow_id = ?");
        args.push((v as i64).into());
    }
    if let Some(k) = q.kind {
        clauses.push("kind = ?");
        args.push(kind_name(k).into());
    }
    let w = if clauses.is_empty() {
        String::new()
    } else {
        format!(" WHERE {}", clauses.join(" AND "))
    };
    let sql = format!(
        "SELECT id, ts, kind, flow_id, host, domain, title, detail FROM events{w} ORDER BY ts, id LIMIT {}",
        q.limit.unwrap_or(10_000).clamp(1, 200_000)
    );
    let mut stmt = db.conn.prepare(&sql)?;
    let rows = stmt.query_map(params_from_iter(args.iter()), from_row)?;
    Ok(rows.collect::<Result<Vec<_>, _>>()?)
}

pub fn event_count(db: &Database) -> Result<u64, CaptureError> {
    db.count("events")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ev(id: u64, ts: i64, kind: EventKind, flow: Option<u64>) -> TimelineEvent {
        TimelineEvent {
            id,
            ts,
            kind,
            flow_id: flow,
            host: Some("140.82.121.4".into()),
            domain: Some("GitHub.com".into()),
            title: format!("event {id}"),
            detail: id.is_multiple_of(2).then(|| "detail".to_string()),
        }
    }

    #[test]
    fn events_round_trip_in_time_order() {
        let mut db = Database::in_memory().unwrap();
        let tx = db.conn.transaction().unwrap();
        let input = vec![
            ev(2, 200, EventKind::Retransmission, Some(1)),
            ev(1, 100, EventKind::DnsQuery, None),
            ev(3, 300, EventKind::TlsHandshake, Some(1)),
        ];
        insert_events(&tx, &input).unwrap();
        tx.commit().unwrap();
        let back = query_events(&db, &EventQuery::default()).unwrap();
        assert_eq!(back.iter().map(|e| e.id).collect::<Vec<_>>(), vec![1, 2, 3]);
        assert_eq!(back[1].kind, EventKind::Retransmission);
        assert_eq!(back[1].detail.as_deref(), Some("detail"));
        assert_eq!(back[0].domain.as_deref(), Some("github.com")); // stored lower-cased
        assert_eq!(event_count(&db).unwrap(), 3);
    }

    #[test]
    fn filters_by_time_flow_and_kind() {
        let mut db = Database::in_memory().unwrap();
        let tx = db.conn.transaction().unwrap();
        insert_events(
            &tx,
            &(1..=20)
                .map(|i| {
                    ev(
                        i,
                        i as i64 * 10,
                        if i % 2 == 0 {
                            EventKind::Retransmission
                        } else {
                            EventKind::FlowStarted
                        },
                        Some(i % 4),
                    )
                })
                .collect::<Vec<_>>(),
        )
        .unwrap();
        tx.commit().unwrap();
        let ids = |q: EventQuery| {
            query_events(&db, &q)
                .unwrap()
                .iter()
                .map(|e| e.id)
                .collect::<Vec<_>>()
        };
        assert_eq!(
            ids(EventQuery {
                ts_from: Some(50),
                ts_to: Some(80),
                ..Default::default()
            }),
            vec![5, 6, 7, 8]
        );
        assert_eq!(
            ids(EventQuery {
                flow_id: Some(0),
                ..Default::default()
            }),
            vec![4, 8, 12, 16, 20]
        );
        assert_eq!(
            ids(EventQuery {
                kind: Some(EventKind::FlowStarted),
                limit: Some(3),
                ..Default::default()
            }),
            vec![1, 3, 5]
        );
    }
}
