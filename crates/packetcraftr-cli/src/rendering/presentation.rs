// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::ops::Deref;
use std::sync::Arc;
use std::time::Duration;

use crate::output;
use packetcraftr_core::budget::Deadline;

/// Immutable human presentation preferences, independent of published schemas.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Presentation {
    pub(crate) verbose: bool,
}

impl Presentation {
    pub(crate) fn details(
        self,
        label: &str,
        value: &impl serde::Serialize,
    ) -> Result<(), crate::errors::CliError> {
        if !self.verbose {
            return Ok(());
        }
        let text = serde_json::to_string_pretty(value).map_err(|error| {
            crate::errors::CliError::new(
                packetcraftr_core::error::Kind::Internal,
                format!("cannot render {label}: {error}"),
            )
        })?;
        super::write_stdout_line(format_args!("{label}:"))?;
        super::emit_stdout_document(&text)
    }
}

/// Carries presentation through the same bounded command and worker lifetimes
/// as the publisher. The public wire encoder remains presentation-independent.
#[derive(Clone)]
pub(crate) struct StreamEncoder {
    encoder: output::stream::StreamEncoder,
    presentation: Presentation,
}

impl StreamEncoder {
    pub(crate) fn new(
        command: output::contract::Command,
        writer: impl std::io::Write + Send + 'static,
    ) -> Self {
        output::stream::StreamEncoder::new(command, writer).into()
    }

    pub(crate) fn presentation(&self) -> Presentation {
        self.presentation
    }

    pub(crate) fn with_presentation(mut self, presentation: Presentation) -> Self {
        self.presentation = presentation;
        self
    }

    pub(crate) fn with_deadline(mut self, deadline: Arc<Deadline>) -> Self {
        self.encoder = self.encoder.with_deadline(deadline);
        self
    }

    pub(crate) fn with_resource_diagnostics(
        mut self,
        observe: impl Fn() -> output::resources::Report + Send + Sync + 'static,
    ) -> Self {
        self.encoder = self.encoder.with_resource_diagnostics(observe);
        self
    }

    pub(crate) fn with_terminal_error_timeout(mut self, timeout: Duration) -> Self {
        self.encoder = self.encoder.with_terminal_error_timeout(timeout);
        self
    }
}

impl From<output::stream::StreamEncoder> for StreamEncoder {
    fn from(encoder: output::stream::StreamEncoder) -> Self {
        Self {
            encoder,
            presentation: Presentation::default(),
        }
    }
}

impl Deref for StreamEncoder {
    type Target = output::stream::StreamEncoder;
    fn deref(&self) -> &Self::Target {
        &self.encoder
    }
}

/// Minimum column widths, not ceilings: identifiers and values never truncate.
/// Each row is written immediately; this does not buffer streams to size columns.
pub(crate) fn table_row(cells: &[(&str, usize)]) -> Result<(), crate::errors::CliError> {
    let mut row = String::new();
    for (index, (value, width)) in cells.iter().enumerate() {
        use std::fmt::Write as _;
        if index != 0 {
            row.push_str("  ");
        }
        let value = super::style::terminal_safe(value);
        let _ = write!(row, "{value:<width$}");
    }
    super::write_stdout_line(format_args!("{}", row.trim_end()))
}
