// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::errors::CliError;
use crate::output;
use crate::output::envelope::Published;
use crate::publication::emit_published;
use crate::terminal::{write_stdout_line, write_summary_line};

pub(crate) fn render_aggregate_rows<T, R: serde::Serialize>(
    invocation: &crate::invocation::Invocation,
    command: output::contract::Command,
    format: output::contract::Format,
    result: &R,
    rows: &[T],
    line: impl Fn(&T) -> String,
) -> Result<(), CliError> {
    match format {
        output::contract::Format::Text => {
            for row in rows {
                write_stdout_line(invocation, format_args!("{}", line(row)))?;
            }
            write_summary_line(
                invocation,
                format_args!("{} {} result(s)", rows.len(), command.as_str()),
            )
        }
        output::contract::Format::Json => {
            emit_published(invocation, command, Published::new(result, Vec::new()))
        }
        other => other.unreachable(),
    }
}
