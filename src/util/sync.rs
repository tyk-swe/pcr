use std::sync::{LockResult, PoisonError};

/// Extension trait for LockResult to easily handle poisoned locks by ignoring the poison.
pub trait LockResultExt<Guard> {
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
    use std::thread;

    #[test]
    fn test_ignore_poison_on_clean_lock() {
        let mutex = Mutex::new(0);
        {
            let mut guard = mutex.lock().ignore_poison();
            *guard += 1;
        }
        assert_eq!(*mutex.lock().unwrap(), 1);
    }

    #[test]
    fn test_ignore_poison_on_poisoned_lock() {
        let mutex = Arc::new(Mutex::new(0));
        let mutex_clone = mutex.clone();

        let _ = thread::spawn(move || {
            let _guard = mutex_clone.lock().unwrap();
            panic!("poisoning the lock");
        })
        .join();

        assert!(mutex.is_poisoned());

        {
            let mut guard = mutex.lock().ignore_poison();
            assert_eq!(*guard, 0);
            *guard += 1;
        }

        // Lock is still poisoned, but data was updated
        let guard = mutex.lock().ignore_poison();
        assert_eq!(*guard, 1);
    }
}
