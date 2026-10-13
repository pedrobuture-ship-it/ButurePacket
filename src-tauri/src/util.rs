//! Small shared helpers.

use std::sync::{Mutex, MutexGuard};

/// Locks a mutex even if another thread panicked while holding it.
///
/// The analysis state is a set of counters and caches that stay internally consistent between
/// updates, so continuing after a panic is safer for the user than cascading the panic through
/// every thread that touches the same data.
pub trait LockRecover<T> {
    fn lock_recover(&self) -> MutexGuard<'_, T>;
}

impl<T> LockRecover<T> for Mutex<T> {
    fn lock_recover(&self) -> MutexGuard<'_, T> {
        self.lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

/// Microseconds as a short duration: "340 µs", "21 ms", "21.4 ms", "250 ms".
pub fn fmt_ms(micros: i64) -> String {
    if micros.abs() < 1_000 {
        return format!("{micros} µs");
    }
    let ms = micros as f64 / 1000.0;
    if ms >= 100.0 {
        format!("{ms:.0} ms")
    } else {
        format!("{ms:.1} ms").replace(".0 ms", " ms")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn durations_read_naturally() {
        assert_eq!(fmt_ms(340), "340 µs");
        assert_eq!(fmt_ms(21_000), "21 ms");
        assert_eq!(fmt_ms(21_400), "21.4 ms");
        assert_eq!(fmt_ms(250_000), "250 ms");
        assert_eq!(fmt_ms(0), "0 µs");
    }

    #[test]
    fn recovers_a_poisoned_lock() {
        let m = Arc::new(Mutex::new(5));
        let m2 = m.clone();
        let _ = std::thread::spawn(move || {
            let _g = m2.lock().unwrap();
            panic!("poison it");
        })
        .join();
        assert!(m.lock().is_err());
        assert_eq!(*m.lock_recover(), 5);
        *m.lock_recover() = 6;
        assert_eq!(*m.lock_recover(), 6);
    }
}
