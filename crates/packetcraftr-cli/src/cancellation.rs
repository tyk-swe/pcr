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

#[cfg(test)]
mod tests {
    use super::{StagedRegistration, remove_staged, signal};
    use crate::invocation::{Invocation, StreamEncoder};
    use crate::output::contract::{Command, Format};
    use packetcraftr_core::budget::Interrupted;
    use std::{
        fs,
        process::{Command as Process, Stdio},
        time::{Duration, Instant},
    };

    fn isolated(name: &str, scenario: impl FnOnce()) {
        if std::env::var("PACKETCRAFTR_CANCELLATION_CASE").is_ok_and(|value| value == name) {
            scenario();
            let marker = std::env::var_os("PACKETCRAFTR_CANCELLATION_COMPLETED").unwrap();
            fs::write(marker, name).unwrap();
            return;
        }
        let directory = tempfile::tempdir().unwrap();
        let marker = directory.path().join("completed");
        let mut child = Process::new(std::env::current_exe().unwrap())
            .args(["--exact", name, "--nocapture"])
            .env("PACKETCRAFTR_CANCELLATION_CASE", name)
            .env("PACKETCRAFTR_CANCELLATION_COMPLETED", &marker)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        while child.try_wait().unwrap().is_none() {
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                panic!("isolated cancellation scenario did not finish");
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        let result = child.wait_with_output().unwrap();
        assert!(
            result.status.success(),
            "{}{}",
            String::from_utf8_lossy(&result.stdout),
            String::from_utf8_lossy(&result.stderr)
        );
        assert_eq!(fs::read(marker).unwrap(), name.as_bytes());
    }

    #[test]
    fn shared_signal_cancels_independent_invocations() {
        isolated(
            "cancellation::tests::shared_signal_cancels_independent_invocations",
            || {
                let handler = signal().clone();
                let invocation = Invocation::new(
                    Format::Text,
                    StreamEncoder::new(Command::Build, std::io::sink()),
                    None,
                    signal().clone(),
                    None,
                );
                invocation.check_interrupted().unwrap();
                handler.cancel();
                assert!(matches!(
                    invocation.check_interrupted(),
                    Err(Interrupted::Cancelled(_))
                ));
            },
        );
    }

    #[test]
    fn forced_cleanup_removes_only_active_registrations() {
        isolated(
            "cancellation::tests::forced_cleanup_removes_only_active_registrations",
            || {
                let directory = tempfile::tempdir().unwrap();
                let active = directory.path().join("active");
                let released = directory.path().join("released");
                fs::write(&active, b"active bytes").unwrap();
                fs::write(&released, b"released bytes").unwrap();
                let _active = StagedRegistration::new(&active);
                let released_registration = StagedRegistration::new(&released);
                drop(released_registration);
                remove_staged();
                assert!(!active.exists());
                assert_eq!(fs::read(released).unwrap(), b"released bytes");
            },
        );
    }
}
