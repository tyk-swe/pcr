// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::errors::{CANCELLED_EXIT_CODE, CliError};
use packetcraftr_core::budget::Cancellation;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard, OnceLock, PoisonError, TryLockError};

static STAGED: Mutex<Vec<PathBuf>> = Mutex::new(Vec::new());

pub(crate) fn signal() -> &'static Cancellation {
    static SIGNAL: OnceLock<Cancellation> = OnceLock::new();
    SIGNAL.get_or_init(Cancellation::default)
}

/// Lists a staged temporary file for removal by a forced exit, which skips
/// destructors, until the registration drops.
#[derive(Debug)]
pub(crate) struct StagedRegistration(PathBuf);

impl StagedRegistration {
    pub(crate) fn new(path: &Path) -> Self {
        staged().push(path.to_owned());
        Self(path.to_owned())
    }
}

impl Drop for StagedRegistration {
    fn drop(&mut self) {
        let mut paths = staged();
        if let Some(index) = paths.iter().position(|path| *path == self.0) {
            paths.swap_remove(index);
        }
    }
}

fn staged() -> MutexGuard<'static, Vec<PathBuf>> {
    STAGED.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Best effort: never waits for the registry, so the exit it precedes cannot hang.
fn remove_staged() {
    let paths = match STAGED.try_lock() {
        Ok(paths) => paths,
        Err(TryLockError::Poisoned(poisoned)) => poisoned.into_inner(),
        Err(TryLockError::WouldBlock) => return,
    };
    for path in paths.iter() {
        let _ = std::fs::remove_file(path);
    }
}

#[cfg(test)]
pub(crate) fn is_staged(path: &Path) -> bool {
    staged().iter().any(|listed| listed == path)
}

pub(crate) fn check() -> Result<(), CliError> {
    signal().check().map_err(CliError::classified)?;
    crate::invocation::check()
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
