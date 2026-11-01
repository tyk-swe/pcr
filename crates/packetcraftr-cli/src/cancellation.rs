// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::errors::{CANCELLED_EXIT_CODE, CliError};
use packetcraftr_core::budget::Cancellation;
use std::sync::{Arc, LazyLock, Mutex, MutexGuard, PoisonError, TryLockError};

static STAGED: Mutex<Vec<Arc<dyn StagedEntry>>> = Mutex::new(Vec::new());

pub(crate) fn signal() -> &'static Cancellation {
    static SIGNAL: LazyLock<Cancellation> = LazyLock::new(Cancellation::default);
    &SIGNAL
}

/// A staged temporary entry that a forced exit removes.
pub(crate) trait StagedEntry: Send + Sync + std::fmt::Debug {
    /// Best effort and without blocking: the process exits right after.
    fn remove(&self);
}

/// Lists a staged temporary entry for removal by a forced exit, which skips
/// destructors, until the registration drops.
#[derive(Debug)]
pub(crate) struct StagedRegistration(Arc<dyn StagedEntry>);

impl StagedRegistration {
    pub(crate) fn new(entry: Arc<dyn StagedEntry>) -> Self {
        staged().push(Arc::clone(&entry));
        Self(entry)
    }
}

impl Drop for StagedRegistration {
    fn drop(&mut self) {
        let mut entries = staged();
        if let Some(index) = entries.iter().position(|entry| Arc::ptr_eq(entry, &self.0)) {
            entries.swap_remove(index);
        }
    }
}

fn staged() -> MutexGuard<'static, Vec<Arc<dyn StagedEntry>>> {
    STAGED.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Best effort: never waits for the registry, so the exit it precedes cannot hang.
fn remove_staged() {
    let entries = match STAGED.try_lock() {
        Ok(entries) => entries,
        Err(TryLockError::Poisoned(poisoned)) => poisoned.into_inner(),
        Err(TryLockError::WouldBlock) => return,
    };
    for entry in entries.iter() {
        entry.remove();
    }
}

pub(crate) fn install() -> Result<(), CliError> {
    let signal = signal().clone();
    ctrlc::set_handler(move || {
        if signal.is_cancelled() {
            remove_staged();
            std::process::exit(i32::from(CANCELLED_EXIT_CODE));
        }
        signal.cancel();
    })
    .map_err(|error| {
        CliError::new(
            packetcraftr_core::error::Kind::Io,
            format!("install interrupt handler failed: {error}"),
        )
    })
}
