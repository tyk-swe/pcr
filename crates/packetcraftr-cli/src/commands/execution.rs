// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::{
    errors::CliError,
    invocation::{Invocation, StreamEncoder},
};
use packetcraftr::Sink;
use packetcraftr_core::budget::Deadline;
use packetcraftr_core::error::BoundaryError;
use std::{sync::Arc, time::Duration};

/// This concrete CLI sink may cooperate when its writer already isolates IO.
/// Text and direct writers preserve the ordinary isolated callback boundary.
pub(crate) enum Emitter<E, F> {
    Cooperative(CooperativeEmitter<F>),
    Isolated(packetcraftr::Isolated<E>),
}

impl<E: Send + 'static, F> Sink<E> for Emitter<E, F>
where
    F: FnMut(E, &StreamEncoder) -> Result<(), CliError> + Send + 'static,
{
    type Ack = ();

    fn publish(&mut self, event: E) -> Result<(), BoundaryError> {
        match self {
            Self::Cooperative(sink) => sink.publish(event),
            Self::Isolated(sink) => sink.publish(event),
        }
    }

    fn publish_controlled(&mut self, event: E, control: &Deadline) -> Result<(), BoundaryError> {
        match self {
            Self::Cooperative(sink) => sink.publish_controlled(event, control),
            Self::Isolated(sink) => sink.publish_controlled(event, control),
        }
    }
}

pub(crate) struct CooperativeEmitter<F> {
    invocation: Invocation,
    publish: F,
}

impl<E, F> Sink<E> for CooperativeEmitter<F>
where
    F: FnMut(E, &StreamEncoder) -> Result<(), CliError> + Send + 'static,
{
    type Ack = ();

    fn publish(&mut self, event: E) -> Result<(), BoundaryError> {
        self.publish_controlled(event, &Deadline::new(Duration::MAX))
    }

    fn publish_controlled(&mut self, event: E, control: &Deadline) -> Result<(), BoundaryError> {
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
        control
            .check_cancelled()
            .map_err(BoundaryError::from_error)?;
        self.invocation
            .control
            .check_cancelled()
            .map_err(BoundaryError::from_error)?;
        result?;
        control.enforce().map_err(BoundaryError::from_error)?;
        self.invocation
            .check()
            .map_err(CliError::into_boundary_error)?;
        Ok(())
    }
}

pub(crate) fn emitter<E, F>(invocation: &Invocation, publish: F) -> Result<Emitter<E, F>, CliError>
where
    E: Send + 'static,
    F: FnMut(E, &StreamEncoder) -> Result<(), CliError> + Send + 'static,
{
    let sink = CooperativeEmitter {
        invocation: invocation.clone(),
        publish,
    };
    if invocation.format == crate::output::contract::Format::Ndjson
        && invocation.output.isolates_writes()
    {
        return Ok(Emitter::Cooperative(sink));
    }
    let runtime = invocation.output_writer_runtime();
    packetcraftr::Isolated::from_sink(&runtime, sink)
        .map(Emitter::Isolated)
        .map_err(CliError::classified)
}

#[cfg(test)]
mod tests;
