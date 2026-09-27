// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use packetcraftr_core::budget::{Deadline, DeadlineExceeded};
use packetcraftr_core::error::BoundaryError;

use crate::runtime::{self, Runtime, Worker};

/// Any `FnMut(E) -> Result<A, BoundaryError>` closure that is `Send + 'static`
/// is a sink.
pub trait Sink<E>: Send + 'static {
    type Ack: Send + 'static;

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
            Err(runtime::Error::Deadline(error)) => Err(on_deadline(error)),
            Err(runtime::Error::Output(source)) => Err(on_output(source)),
        },
    )
}
