// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

mod encoder;

pub(crate) use encoder::{Presentation, StreamEncoder};

use crate::{
    errors::CliError,
    output::{contract::Format, envelope::Envelope},
    resources::Diagnostics,
};
use packetcraftr_core::budget::{Cancellation, Deadline, Interrupted};
use std::{
    sync::{
        Arc, Mutex, MutexGuard, PoisonError,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

/// One command's stop conditions. Consumers that only read inputs or run
/// bounded work take this without the command's output state.
#[derive(Clone, Debug)]
pub(crate) struct Control {
    pub(crate) deadline: Option<Arc<Deadline>>,
    pub(crate) cancellation: Cancellation,
}

impl Control {
    pub(crate) fn new(duration: Option<Duration>, cancellation: Cancellation) -> Self {
        let deadline = duration.map(|duration| {
            Arc::new(Deadline::new(duration).with_cancellation(Some(cancellation.clone())))
        });
        Self {
            deadline,
            cancellation,
        }
    }

    /// Terminal error cleanup is allowed after the execution/publication ceiling.
    pub(crate) fn terminal() -> Self {
        Self {
            deadline: None,
            cancellation: Cancellation::default(),
        }
    }

    /// The control the output encoder enforces, always finite in effect
    /// through cancellation even without a duration.
    fn output_control(&self) -> Arc<Deadline> {
        self.deadline.clone().unwrap_or_else(|| {
            Arc::new(
                Deadline::new(Duration::MAX).with_cancellation(Some(self.cancellation.clone())),
            )
        })
    }

    pub(crate) fn check_interrupted(&self) -> Result<(), Interrupted> {
        self.cancellation.check()?;
        if let Some(deadline) = &self.deadline {
            deadline.enforce()?;
        }
        Ok(())
    }

    pub(crate) fn check(&self) -> Result<(), CliError> {
        self.check_interrupted().map_err(CliError::classified)
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
}

/// One command's output, stop conditions, and optional resource diagnostics.
/// Clones passed to workers share these bounds and diagnostics, never ambient state.
#[derive(Clone)]
pub(crate) struct Invocation {
    pub(crate) format: Format,
    pub(crate) output: StreamEncoder,
    pub(crate) control: Control,
    pub(crate) diagnostics: Option<Arc<Diagnostics>>,
    json_attempted: Arc<AtomicBool>,
    stdout_batch: Arc<Mutex<Option<Vec<u8>>>>,
}

impl Invocation {
    pub(crate) fn new(
        format: Format,
        output: StreamEncoder,
        duration: Option<Duration>,
        cancellation: Cancellation,
        diagnostics: Option<Arc<Diagnostics>>,
    ) -> Self {
        Self {
            format,
            output,
            control: Control::new(duration, cancellation),
            diagnostics,
            json_attempted: Arc::new(AtomicBool::new(false)),
            stdout_batch: Arc::default(),
        }
        .configure_output()
    }

    /// Holds human stdout back until flushed. Only commands that write nothing to stderr
    /// before they finish may call this, or the two streams could trade places.
    pub(crate) fn batch_stdout(&self) {
        *self.stdout_batch() = Some(Vec::new());
    }

    pub(crate) fn stdout_batch(&self) -> MutexGuard<'_, Option<Vec<u8>>> {
        self.stdout_batch
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    pub(crate) fn with_output(mut self, output: StreamEncoder) -> Self {
        self.output = output;
        self.configure_output()
    }

    fn configure_output(mut self) -> Self {
        let output = self.output.with_control(self.control.output_control());
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
            control: Control::terminal(),
            output: self.output.clone().terminal(),
            ..self.clone()
        }
    }

    pub(crate) fn check_interrupted(&self) -> Result<(), Interrupted> {
        self.control.check_interrupted()
    }

    pub(crate) fn check(&self) -> Result<(), CliError> {
        self.control.check()
    }

    pub(crate) fn json_attempted(&self) -> bool {
        self.json_attempted.load(Ordering::Relaxed)
    }

    /// An aggregate invocation may publish only one JSON document, even after failure.
    pub(crate) fn begin_json(&self) -> Result<(), CliError> {
        if self.json_attempted.swap(true, Ordering::Relaxed) {
            return Err(CliError::new(
                packetcraftr_core::error::Kind::Internal,
                "JSON output publication was already attempted",
            ));
        }
        Ok(())
    }

    pub(crate) fn passive_lookup(&self) -> Deadline {
        self.control.passive_lookup()
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

    /// A single-worker runtime for this invocation's output writer, reported
    /// in its resource diagnostics.
    pub(crate) fn output_writer_runtime(&self) -> packetcraftr::runtime::Runtime {
        let runtime = packetcraftr::runtime::Runtime::new(1)
            .expect("a capacity of one is within the ceiling");
        self.register_runtime("output_writer", &runtime);
        runtime
    }

    pub(crate) fn stream_index_needed(&self, needed: bool) {
        if let Some(diagnostics) = &self.diagnostics {
            diagnostics.stream_index_needed(needed);
        }
    }
}

impl std::fmt::Debug for Invocation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Invocation")
            .field("format", &self.format)
            .field("deadline", &self.control.deadline)
            .finish_non_exhaustive()
    }
}
