// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::{
    errors::CliError,
    output::{contract::Format, envelope::Envelope},
    rendering::StreamEncoder,
    resources::Diagnostics,
};
use packetcraftr_core::budget::{Cancellation, Deadline, Interrupted};
use std::{sync::Arc, time::Duration};

/// One command's output, stop conditions, and optional resource diagnostics.
/// Clones passed to workers share these bounds and diagnostics, never ambient state.
#[derive(Clone)]
pub(crate) struct Invocation {
    pub(crate) format: Format,
    pub(crate) output: StreamEncoder,
    pub(crate) deadline: Option<Arc<Deadline>>,
    pub(crate) cancellation: Cancellation,
    pub(crate) diagnostics: Option<Arc<Diagnostics>>,
}

impl Invocation {
    pub(crate) fn new(
        format: Format,
        output: StreamEncoder,
        duration: Option<Duration>,
        cancellation: Cancellation,
        diagnostics: Option<Arc<Diagnostics>>,
    ) -> Self {
        let deadline = duration.map(|duration| {
            Arc::new(Deadline::new(duration).with_cancellation(Some(cancellation.clone())))
        });
        Self {
            format,
            output,
            deadline,
            cancellation,
            diagnostics,
        }
        .configure_output()
    }

    pub(crate) fn with_output(mut self, output: StreamEncoder) -> Self {
        self.output = output;
        self.configure_output()
    }

    fn configure_output(mut self) -> Self {
        let control = self.deadline.clone().unwrap_or_else(|| {
            Arc::new(
                Deadline::new(Duration::MAX).with_cancellation(Some(self.cancellation.clone())),
            )
        });
        let output = self.output.with_control(control);
        self.output = match &self.diagnostics {
            Some(diagnostics) => {
                let diagnostics = diagnostics.clone();
                output.with_resource_diagnostics(move || diagnostics.snapshot())
            }
            None => output,
        };
        self
    }

    /// Terminal error cleanup is allowed after the execution/publication ceiling.
    pub(crate) fn terminal(&self) -> Self {
        Self {
            deadline: None,
            output: self.output.clone().terminal(),
            cancellation: Cancellation::default(),
            ..self.clone()
        }
    }

    pub(crate) fn check_interrupted(&self) -> Result<(), Interrupted> {
        self.cancellation.check()?;
        if let Some(deadline) = &self.deadline {
            deadline.enforce()?;
        }
        Ok(())
    }

    pub(crate) fn check(&self) -> Result<(), CliError> {
        self.check_interrupted().map_err(interruption_error)
    }

    pub(crate) fn passive_lookup(&self) -> Deadline {
        Deadline::new(packetcraftr::deadline::PASSIVE_LOOKUP_TIMEOUT)
            .with_parent(self.deadline.clone())
            .with_cancellation(Some(self.cancellation.clone()))
    }

    pub(crate) fn reader<R: std::io::Read>(
        &self,
        reader: packetcraftr_core::capture_file::Reader<R>,
    ) -> packetcraftr_core::capture_file::Reader<R> {
        let reader = reader.with_cancellation(self.cancellation.clone());
        match &self.deadline {
            Some(deadline) => reader.with_deadline(deadline.clone()),
            None => reader,
        }
    }

    pub(crate) fn decorate<T>(&self, envelope: Envelope<T>) -> Envelope<T> {
        match &self.diagnostics {
            Some(diagnostics) => envelope.with_resources(diagnostics.snapshot()),
            None => envelope,
        }
    }

    pub(crate) fn register_runtime(
        &self,
        name: &'static str,
        runtime: &packetcraftr::runtime::Runtime,
    ) {
        if let Some(diagnostics) = &self.diagnostics {
            diagnostics.register_runtime(name, runtime);
        }
    }

    pub(crate) fn stream_index_needed(&self, needed: bool) {
        if let Some(diagnostics) = &self.diagnostics {
            diagnostics.stream_index_needed(needed);
        }
    }
}

pub(crate) fn interruption_error(error: Interrupted) -> CliError {
    CliError::classified(error)
}

impl std::fmt::Debug for Invocation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Invocation")
            .field("format", &self.format)
            .field("deadline", &self.deadline)
            .finish_non_exhaustive()
    }
}
