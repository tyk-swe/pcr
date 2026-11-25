// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use packetcraftr_core::budget::{Deadline, DeadlineExceeded};
use packetcraftr_core::error::BoundaryError;

use crate::runtime::{Runtime, Worker};

/// A progressive event consumer. Sinks run in the caller unless explicitly
/// wrapped in [`Isolated`], so borrowed state can be passed with `&mut`.
pub trait Sink<E> {
    type Ack;

    fn publish(&mut self, event: E) -> Result<Self::Ack, BoundaryError>;

    fn publish_controlled(
        &mut self,
        event: E,
        _control: &Deadline,
    ) -> Result<Self::Ack, BoundaryError> {
        self.publish(event)
    }
}

impl<E, S> Sink<E> for &mut S
where
    S: Sink<E> + ?Sized,
{
    type Ack = S::Ack;

    fn publish(&mut self, event: E) -> Result<Self::Ack, BoundaryError> {
        (**self).publish(event)
    }

    fn publish_controlled(
        &mut self,
        event: E,
        control: &Deadline,
    ) -> Result<Self::Ack, BoundaryError> {
        (**self).publish_controlled(event, control)
    }
}

/// Worker-thread isolation for a blocking sink. This is the boundary that
/// requires owned, sendable state; unwrapped sinks remain cooperative.
pub struct Isolated<E, A = ()> {
    worker: Worker<(E, Deadline), A>,
}

impl<E, A> Isolated<E, A> {
    pub fn new<Emit>(runtime: &Runtime, emit: Emit) -> Result<Self, BoundaryError>
    where
        Emit: FnMut((E, Deadline)) -> Result<A, BoundaryError> + Send + 'static,
        E: Send + 'static,
        A: Send + 'static,
    {
        Ok(Self {
            worker: Worker::new_in(runtime, emit)?,
        })
    }

    pub fn from_sink<S>(runtime: &Runtime, mut sink: S) -> Result<Self, BoundaryError>
    where
        S: Sink<E, Ack = A> + Send + 'static,
        E: Send + 'static,
        A: Send + 'static,
    {
        Self::new(runtime, move |(event, control): (E, Deadline)| {
            sink.publish_controlled(event, &control)
        })
    }
}

impl<E, A> Sink<E> for Isolated<E, A>
where
    E: Send + 'static,
    A: Send + 'static,
{
    type Ack = A;

    fn publish(&mut self, event: E) -> Result<A, BoundaryError> {
        self.publish_controlled(event, &Deadline::new(std::time::Duration::MAX))
    }

    fn publish_controlled(&mut self, event: E, control: &Deadline) -> Result<A, BoundaryError> {
        self.worker
            .emit((event, control.clone()), control)
            .map_err(|error| match error {
                crate::runtime::Error::Deadline(error) => BoundaryError::from_error(error),
                crate::runtime::Error::Output(error) => error,
            })
    }
}

pub fn forwarding<E, A, F>(callback: F) -> impl Sink<E, Ack = A>
where
    F: FnMut(E, Option<&Deadline>) -> Result<A, BoundaryError>,
{
    struct Forward<F> {
        callback: F,
    }
    impl<E, A, F> Sink<E> for Forward<F>
    where
        F: FnMut(E, Option<&Deadline>) -> Result<A, BoundaryError>,
    {
        type Ack = A;
        fn publish(&mut self, event: E) -> Result<A, BoundaryError> {
            (self.callback)(event, None)
        }
        fn publish_controlled(&mut self, event: E, control: &Deadline) -> Result<A, BoundaryError> {
            (self.callback)(event, Some(control))
        }
    }
    Forward { callback }
}

pub(crate) fn publisher<E, S, X>(
    mut sink: S,
    on_deadline: impl Fn(DeadlineExceeded) -> X,
    on_output: impl Fn(BoundaryError) -> X,
) -> Result<impl FnMut(E, &Deadline) -> Result<S::Ack, X>, X>
where
    S: Sink<E>,
{
    Ok(move |event, deadline: &Deadline| {
        fn interrupted<X>(
            source: packetcraftr_core::budget::Interrupted,
            on_deadline: &impl Fn(DeadlineExceeded) -> X,
            on_output: &impl Fn(BoundaryError) -> X,
        ) -> X {
            match source {
                packetcraftr_core::budget::Interrupted::Cancelled(cancelled) => {
                    on_output(BoundaryError::from_error(cancelled))
                }
                packetcraftr_core::budget::Interrupted::Exceeded(expired) => on_deadline(expired),
                other => on_output(BoundaryError::from_error(other)),
            }
        }
        if let Err(source) = deadline.enforce() {
            return Err(interrupted(source, &on_deadline, &on_output));
        }
        match sink.publish_controlled(event, deadline) {
            Ok(ack) => match deadline.enforce() {
                Ok(()) => Ok(ack),
                Err(source) => Err(interrupted(source, &on_deadline, &on_output)),
            },
            Err(error) => {
                if let Err(source) = deadline.enforce() {
                    return Err(interrupted(source, &on_deadline, &on_output));
                }
                Err(on_output(error))
            }
        }
    })
}

#[cfg(test)]
mod tests;
