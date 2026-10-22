// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::{
    errors::CliError,
    invocation::{Invocation, StreamEncoder},
};
use packetcraftr::{Delivery, Sink};
use packetcraftr_core::budget::Deadline;
use packetcraftr_core::error::BoundaryError;
use std::{sync::Arc, time::Duration};

/// This concrete CLI sink may cooperate when its writer already isolates IO.
/// Text and direct writers preserve the ordinary isolated callback boundary.
pub(crate) fn emitter<E: 'static>(
    invocation: &Invocation,
    publish: impl FnMut(E, &StreamEncoder) -> Result<(), CliError> + Send + 'static,
) -> impl Sink<E, Ack = ()> {
    struct Emitter<F> {
        invocation: Invocation,
        publish: F,
        delivery: Delivery,
    }
    impl<E, F> Sink<E> for Emitter<F>
    where
        F: FnMut(E, &StreamEncoder) -> Result<(), CliError> + Send + 'static,
    {
        type Ack = ();
        fn delivery(&self) -> Delivery {
            self.delivery
        }
        fn publish(&mut self, event: E) -> Result<(), BoundaryError> {
            self.publish_controlled(event, &Deadline::new(Duration::MAX))
        }
        fn publish_controlled(
            &mut self,
            event: E,
            control: &Deadline,
        ) -> Result<(), BoundaryError> {
            let control = control.detach().map_err(BoundaryError::from_error)?;
            control.enforce().map_err(BoundaryError::from_error)?;
            self.invocation
                .check()
                .map_err(CliError::into_boundary_error)?;
            let output = self
                .invocation
                .output
                .clone()
                .with_control(Arc::new(control.clone()));
            let result = (self.publish)(event, &output).map_err(CliError::into_boundary_error);
            control.enforce().map_err(BoundaryError::from_error)?;
            self.invocation
                .check()
                .map_err(CliError::into_boundary_error)?;
            result
        }
    }
    let delivery = if invocation.format == crate::output::contract::Format::Ndjson
        && invocation.output.isolates_writes()
    {
        Delivery::Cooperative
    } else {
        Delivery::Isolated
    };
    Emitter {
        invocation: invocation.clone(),
        publish,
        delivery,
    }
}

#[cfg(test)]
mod tests;
