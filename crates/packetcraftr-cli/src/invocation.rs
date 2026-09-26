// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! The synchronous CLI dispatch scope. Library operations receive their
//! deadlines explicitly; this scope joins input, rendering and publication
//! boundaries without changing every command's argument model.

use crate::errors::CliError;
use packetcraftr_core::budget::{Deadline, Interrupted};
use packetcraftr_core::error::{Classification, Kind};
use std::cell::RefCell;
use std::sync::Arc;
use std::time::Duration;

thread_local! {
    static CURRENT: RefCell<Option<Arc<Deadline>>> = const { RefCell::new(None) };
}

pub(crate) struct Guard {
    previous: Option<Arc<Deadline>>,
}

pub(crate) fn enter(duration: Option<Duration>) -> Guard {
    let next = duration.map(|duration| {
        Arc::new(
            Deadline::new(duration).with_cancellation(Some(crate::cancellation::signal().clone())),
        )
    });
    enter_deadline(next)
}

pub(crate) fn enter_deadline(next: Option<Arc<Deadline>>) -> Guard {
    Guard {
        previous: CURRENT.with(|current| current.replace(next)),
    }
}

impl Drop for Guard {
    fn drop(&mut self) {
        CURRENT.with(|current| {
            current.replace(self.previous.take());
        });
    }
}

pub(crate) fn deadline() -> Option<Arc<Deadline>> {
    CURRENT.with(|current| current.borrow().clone())
}

pub(crate) fn check() -> Result<(), CliError> {
    check_interrupted().map_err(interruption_error)
}

pub(crate) fn interruption_error(error: Interrupted) -> CliError {
    match error {
        Interrupted::Cancelled(error) => CliError::classified(error),
        Interrupted::Exceeded(error) => CliError::from_classification(
            Classification::new(
                "policy.duration_limit",
                Kind::Policy,
                Some("reduce work or raise the finite invocation duration"),
            ),
            error.to_string(),
            Vec::new(),
        ),
        other => CliError::new(Kind::Policy, other.to_string()),
    }
}

pub(crate) fn check_interrupted() -> Result<(), Interrupted> {
    if let Some(deadline) = deadline() {
        deadline.enforce()?;
    }
    Ok(())
}

/// Attach the same clock to every reader, including seekable snapshots.
pub(crate) fn reader<R: std::io::Read>(
    reader: packetcraftr_core::capture_file::Reader<R>,
) -> packetcraftr_core::capture_file::Reader<R> {
    match deadline() {
        Some(deadline) => reader.with_deadline(deadline),
        None => reader,
    }
}
