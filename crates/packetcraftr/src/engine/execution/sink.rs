// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use packetcraftr_core::budget::{Deadline, DeadlineExceeded};
use packetcraftr_core::error::BoundaryError;

use crate::runtime::{self, Runtime, Worker};

/// Where publication executes. Cooperative sinks must return promptly; checks
/// surround their callback, but cannot preempt synchronous work inside it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Delivery {
    #[default]
    Isolated,
    Cooperative,
}

/// Any `FnMut(E) -> Result<A, BoundaryError>` closure that is `Send + 'static`
/// is a sink.
pub trait Sink<E>: Send + 'static {
    type Ack: Send + 'static;

    fn publish(&mut self, event: E) -> Result<Self::Ack, BoundaryError>;

    /// Publication with the operation's effective control. The default keeps
    /// existing callback semantics; cooperative adapters may carry this control
    /// into their own bounded waits. Synchronous callbacks cannot be preempted.
    fn publish_controlled(
        &mut self,
        event: E,
        _control: &Deadline,
    ) -> Result<Self::Ack, BoundaryError> {
        self.publish(event)
    }

    /// Arbitrary callbacks retain the isolated, acknowledged worker default.
    fn delivery(&self) -> Delivery {
        Delivery::Isolated
    }
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

/// Preserve an existing sink's declared delivery while adding bounded tracking
/// or changing its event type. Acknowledgements retain their original meaning.
pub(crate) fn forwarding<E, A, F>(delivery: Delivery, callback: F) -> impl Sink<E, Ack = A>
where
    E: 'static,
    A: Send + 'static,
    F: FnMut(E, Option<&Deadline>) -> Result<A, BoundaryError> + Send + 'static,
{
    struct Forward<F> {
        delivery: Delivery,
        callback: F,
    }
    impl<E, A, F> Sink<E> for Forward<F>
    where
        A: Send + 'static,
        F: FnMut(E, Option<&Deadline>) -> Result<A, BoundaryError> + Send + 'static,
    {
        type Ack = A;
        fn delivery(&self) -> Delivery {
            self.delivery
        }
        fn publish(&mut self, event: E) -> Result<A, BoundaryError> {
            (self.callback)(event, None)
        }
        fn publish_controlled(&mut self, event: E, control: &Deadline) -> Result<A, BoundaryError> {
            (self.callback)(event, Some(control))
        }
    }
    Forward { delivery, callback }
}

pub(crate) fn publisher<E, S, X>(
    runtime: &Runtime,
    sink: S,
    on_deadline: impl Fn(DeadlineExceeded) -> X,
    on_output: impl Fn(BoundaryError) -> X,
) -> Result<impl FnMut(E, &Deadline) -> Result<S::Ack, X>, X>
where
    E: Send + 'static,
    S: Sink<E>,
{
    enum Publisher<E, S: Sink<E>> {
        Cooperative(S),
        Isolated(Worker<(E, Deadline), S::Ack>),
    }
    let mut publisher = match sink.delivery() {
        Delivery::Cooperative => Publisher::Cooperative(sink),
        Delivery::Isolated => {
            let mut sink = sink;
            Publisher::Isolated(
                Worker::new_in(runtime, move |(event, control): (E, Deadline)| {
                    sink.publish_controlled(event, &control)
                })
                .map_err(&on_output)?,
            )
        }
    };
    Ok(move |event, deadline: &Deadline| {
        let result = (|| {
            let deadline = deadline.detach().map_err(runtime::Error::from)?;
            match &mut publisher {
                Publisher::Isolated(worker) => worker.emit((event, deadline.clone()), &deadline),
                Publisher::Cooperative(sink) => (|| {
                    deadline.enforce().map_err(runtime::Error::from)?;
                    let result = sink
                        .publish_controlled(event, &deadline)
                        .map_err(runtime::Error::Output);
                    deadline.enforce().map_err(runtime::Error::from)?;
                    result
                })(),
            }
        })();
        match result {
            Ok(ack) => Ok(ack),
            Err(runtime::Error::Deadline(error)) => Err(on_deadline(error)),
            Err(runtime::Error::Output(source)) => Err(on_output(source)),
        }
    })
}

#[cfg(test)]
mod tests;
