// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

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
        let value = super::sanitize::terminal_safe(value);
        let _ = write!(row, "{value:<width$}");
    }
    super::stdout::write_stdout_line(invocation, format_args!("{}", row.trim_end()))
}
