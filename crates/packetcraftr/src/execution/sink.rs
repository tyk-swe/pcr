// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! The one event-sink contract and its publication on a runtime worker.

use packetcraftr_core::budget::{Deadline, DeadlineExceeded};
use packetcraftr_core::error::BoundaryError;

use crate::runtime::{EmitError, Runtime, Worker};

/// Receives the events one workflow run publishes while it runs.
///
/// Each event is handed to the sink on a worker thread admitted by the
/// caller's [`Runtime`], and the workflow waits, no longer than its deadline,
/// for the sink's answer before it continues. The run itself returns the
/// terminal report. A failed publication stops the run and is reported as the
/// workflow's output failure.
///
/// Any `FnMut(E) -> Result<A, BoundaryError>` closure that is `Send + 'static`
/// is a sink.
pub trait Sink<E>: Send + 'static {
    /// What the sink answers for each event; `()` when the workflow needs no
    /// answer.
    type Ack: Send + 'static;

    /// Handles one event.
    ///
    /// # Errors
    ///
    /// Returns the boundary failure that stops the workflow.
    fn publish(&mut self, event: E) -> Result<Self::Ack, BoundaryError>;
}

impl<E, A, F> Sink<E> for F
where
    F: FnMut(E) -> Result<A, BoundaryError> + Send + 'static,
    A: Send + 'static,
{
    type Ack = A;

    fn publish(&mut self, event: E) -> Result<A, BoundaryError> {
        self(event)
    }
}

/// Runs `sink` on a worker admitted by `runtime` and returns the publisher a
/// workflow calls for each event, which adapts both publication failures into
/// the workflow's own error type. Every workflow that publishes events goes
/// through this adapter.
pub(crate) fn publisher<E, S, X>(
    runtime: &Runtime,
    mut sink: S,
    on_deadline: impl Fn(DeadlineExceeded) -> X,
    on_output: impl Fn(BoundaryError) -> X,
) -> Result<impl FnMut(E, &Deadline) -> Result<S::Ack, X>, X>
where
    E: Send + 'static,
    S: Sink<E>,
{
    let worker = Worker::new_in(runtime, move |event| sink.publish(event)).map_err(&on_output)?;
    Ok(
        move |event, deadline: &Deadline| match worker.emit(event, deadline) {
            Ok(ack) => Ok(ack),
            Err(EmitError::Deadline(error)) => Err(on_deadline(error)),
            Err(EmitError::Output(source)) => Err(on_output(source)),
        },
    )
}
