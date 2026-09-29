// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::errors::CliError;
use packetcraftr_core::budget::{Deadline, Interrupted};
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

pub(crate) fn passive_lookup() -> Deadline {
    Deadline::new(packetcraftr::deadline::PASSIVE_LOOKUP_TIMEOUT)
        .with_parent(deadline())
        .with_cancellation(Some(crate::cancellation::signal().clone()))
}

pub(crate) fn check() -> Result<(), CliError> {
    check_interrupted().map_err(interruption_error)
}

pub(crate) fn interruption_error(error: Interrupted) -> CliError {
    CliError::classified(error)
}

pub(crate) fn check_interrupted() -> Result<(), Interrupted> {
    if let Some(deadline) = deadline() {
        deadline.enforce()?;
    }
    Ok(())
}

pub(crate) fn reader<R: std::io::Read>(
    reader: packetcraftr_core::capture_file::Reader<R>,
) -> packetcraftr_core::capture_file::Reader<R> {
    match deadline() {
        Some(deadline) => reader.with_deadline(deadline),
        None => reader,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use packetcraftr_core::budget::{Cancelled, DeadlineExceeded};
    use packetcraftr_core::error::Classified;

    #[test]
    fn interruptions_publish_the_classification_their_library_owns() {
        let exceeded = DeadlineExceeded {
            actual: Duration::from_millis(2),
            limit: Duration::from_millis(1),
        };
        for interrupted in [
            Interrupted::Cancelled(Cancelled),
            Interrupted::Exceeded(exceeded),
        ] {
            let error = interruption_error(interrupted);
            assert_eq!(error.classification, interrupted.classification());
            assert_eq!(error.message, interrupted.to_string());
        }
    }
}
