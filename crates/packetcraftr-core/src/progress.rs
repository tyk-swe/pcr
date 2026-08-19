// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Deadline-aware publication for progressive operation events.

use std::sync::mpsc::{self, RecvTimeoutError, SyncSender, TrySendError};
use std::thread;
use std::time::Duration;

use crate::budget::{Deadline, DeadlineExceeded};
use crate::error::{BoundaryError, Classification, Kind};

/// Failure returned by an interruptible progressive sink.
#[derive(Debug)]
pub enum EmitError {
    Deadline(DeadlineExceeded),
    Output(BoundaryError),
}

/// Runs a user callback on an isolated worker and bounds every publication by
/// the operation deadline.
pub struct Sink<T> {
    events: SyncSender<T>,
    outcomes: mpsc::Receiver<Result<(), BoundaryError>>,
}

impl<T: Send + 'static> Sink<T> {
    /// Starts a bounded one-event worker for `emit`.
    pub fn new<F>(mut emit: F) -> Result<Self, BoundaryError>
    where
        F: FnMut(T) -> Result<(), BoundaryError> + Send + 'static,
    {
        let (events, event_receiver) = mpsc::sync_channel(1);
        let (outcomes, outcome_receiver) = mpsc::sync_channel(1);
        thread::Builder::new()
            .name("packetcraftr-progress".to_owned())
            .spawn(move || {
                while let Ok(event) = event_receiver.recv() {
                    let outcome = emit(event);
                    let failed = outcome.is_err();
                    if outcomes.send(outcome).is_err() || failed {
                        break;
                    }
                }
            })
            .map_err(|source| {
                BoundaryError::with_source(
                    format!("start progressive output worker failed: {source}"),
                    output_classification(),
                    Vec::new(),
                    source,
                )
            })?;
        Ok(Self {
            events,
            outcomes: outcome_receiver,
        })
    }

    /// Publishes one event and waits for its callback result no longer than
    /// `deadline` permits.
    pub fn emit(&self, event: T, deadline: &Deadline) -> Result<(), EmitError> {
        deadline.check().map_err(EmitError::Deadline)?;
        self.events.try_send(event).map_err(|error| match error {
            TrySendError::Full(_) => EmitError::Output(unavailable(
                "progressive output accepted more than one in-flight event",
            )),
            TrySendError::Disconnected(_) => EmitError::Output(unavailable(
                "progressive output worker stopped unexpectedly",
            )),
        })?;
        loop {
            let remaining = deadline.remaining().map_err(EmitError::Deadline)?;
            match self.outcomes.recv_timeout(remaining) {
                Ok(outcome) => return outcome.map_err(EmitError::Output),
                Err(RecvTimeoutError::Disconnected) => {
                    return Err(EmitError::Output(unavailable(
                        "progressive output worker stopped without a result",
                    )));
                }
                Err(RecvTimeoutError::Timeout) => {
                    deadline.check().map_err(EmitError::Deadline)?;
                    if remaining == Duration::ZERO {
                        thread::yield_now();
                    }
                }
            }
        }
    }
}

fn unavailable(message: &'static str) -> BoundaryError {
    BoundaryError::new(message, output_classification(), Vec::new())
}

const fn output_classification() -> Classification {
    Classification::new(
        "internal.progressive_output",
        Kind::Internal,
        Some("treat the progressive operation as incomplete and inspect the event callback"),
    )
}

#[cfg(test)]
mod tests {
    use std::sync::mpsc;
    use std::time::{Duration, Instant};

    use super::*;

    #[test]
    fn blocked_callback_cannot_outlive_the_publication_deadline() {
        let (release, wait) = mpsc::channel();
        let sink = Sink::new(move |(): ()| {
            wait.recv().expect("test releases callback");
            Ok(())
        })
        .unwrap();
        let deadline = Deadline::new(Duration::from_millis(10));
        let started = Instant::now();
        assert!(matches!(
            sink.emit((), &deadline),
            Err(EmitError::Deadline(_))
        ));
        assert!(started.elapsed() < Duration::from_secs(1));
        release.send(()).unwrap();
    }

    #[test]
    fn callback_classification_is_returned_unchanged() {
        let sink = Sink::new(|(): ()| {
            Err(BoundaryError::new(
                "denied",
                Classification::new("policy.fixture", Kind::Policy, None),
                Vec::new(),
            ))
        })
        .unwrap();
        let error = sink
            .emit((), &Deadline::new(Duration::from_secs(1)))
            .expect_err("callback fails");
        let EmitError::Output(error) = error else {
            panic!("callback failure must remain output failure")
        };
        assert_eq!(
            crate::error::Classified::classification(&error).code,
            "policy.fixture"
        );
    }
}
