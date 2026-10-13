//! Persistence: a bounded in-memory raw-packet store for payload lookups, plus a SQLite layer
//! (derived records only, never raw bytes) written in batches by a background thread.

pub mod database;
pub mod dns;
pub mod events;
pub mod flows;
pub mod memory;
pub mod packets;
pub mod writer;

/// SQLite integers are signed 64-bit. Values that came from outside (query parameters) are
/// clamped instead of wrapping, so `u64::MAX` can never turn into a negative number.
pub(crate) fn sql_id(v: u64) -> i64 {
    i64::try_from(v).unwrap_or(i64::MAX)
}

#[cfg(test)]
mod tests {
    use super::sql_id;

    #[test]
    fn ids_clamp_instead_of_wrapping() {
        assert_eq!(sql_id(5), 5);
        assert_eq!(sql_id(i64::MAX as u64), i64::MAX);
        assert_eq!(sql_id(u64::MAX), i64::MAX);
    }
}
