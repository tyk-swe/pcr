// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Rendering that follows the invocation's presentation preferences.

use crate::invocation::Presentation;

impl Presentation {
    pub(crate) fn details(
        self,
        invocation: &crate::invocation::Invocation,
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
        super::write_stdout_line(invocation, format_args!("{label}:"))?;
        super::emit_stdout_document(invocation, &text)
    }
}

/// Minimum column widths, not ceilings: identifiers and values never truncate.
/// Each row is written immediately; this does not buffer streams to size columns.
pub(crate) fn table_row(
    invocation: &crate::invocation::Invocation,
    cells: &[(&str, usize)],
) -> Result<(), crate::errors::CliError> {
    let mut row = String::new();
    for (index, (value, width)) in cells.iter().enumerate() {
        use std::fmt::Write as _;
        if index != 0 {
            row.push_str("  ");
        }
        let value = super::style::terminal_safe(value);
        let _ = write!(row, "{value:<width$}");
    }
    super::write_stdout_line(invocation, format_args!("{}", row.trim_end()))
}
