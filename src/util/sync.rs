// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::{LockResult, PoisonError};

/// Extension trait for LockResult to easily handle poisoned locks by ignoring the poison.
pub(crate) trait LockResultExt<Guard> {
    /// Returns the guard, ignoring whether the lock is poisoned or not.
    ///
    /// This is equivalent to `unwrap_or_else(PoisonError::into_inner)`.
    fn ignore_poison(self) -> Guard;
}

impl<Guard> LockResultExt<Guard> for LockResult<Guard> {
    fn ignore_poison(self) -> Guard {
        self.unwrap_or_else(PoisonError::into_inner)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    #[test]
    fn ignore_poison_returns_guard_for_healthy_lock() {
        let lock = Mutex::new(41);

        let mut guard = lock.lock().ignore_poison();
        *guard += 1;

        assert_eq!(*guard, 42);
    }

    #[test]
    fn ignore_poison_recovers_guard_after_panic_while_locked() {
        let lock = Arc::new(Mutex::new(7));
        let thread_lock = Arc::clone(&lock);
        let _ = std::thread::spawn(move || {
            let _guard = thread_lock.lock().unwrap();
            panic!("poison lock for test");
        })
        .join();

        let guard = lock.lock().ignore_poison();

        assert_eq!(*guard, 7);
    }
}
