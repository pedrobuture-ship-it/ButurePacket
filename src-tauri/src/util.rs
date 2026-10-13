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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

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
