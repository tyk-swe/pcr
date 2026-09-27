// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Row-oriented text and aggregate JSON publication.

use super::{emit_aggregate, write_stdout_line};
use crate::errors::CliError;
use crate::output;

/// Renders one aggregate row per text line, or the whole result as one JSON
/// document.
pub(crate) fn render_aggregate_rows<T, R: serde::Serialize>(
    command: output::contract::Command,
    format: output::contract::AggregateFormat,
    result: &R,
    rows: &[T],
    line: impl Fn(&T) -> String,
) -> Result<(), CliError> {
    match format {
        output::contract::AggregateFormat::Text => {
            for row in rows {
                write_stdout_line(format_args!("{}", line(row)))?;
            }
            Ok(())
        }
        output::contract::AggregateFormat::Json => emit_aggregate(command, result, Vec::new()),
    }
}
