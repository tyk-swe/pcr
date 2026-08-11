// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use packetcraftr::output;
use serde::Serialize;

use super::super::errors::CliError;
use super::human::write_machine_line;

pub(crate) fn render_optional<T>(value: Option<T>, render: impl FnOnce(T) -> String) -> String {
    value.map_or_else(|| "none".to_owned(), render)
}

pub(crate) fn optional_display<T: std::fmt::Display>(value: Option<T>) -> String {
    render_optional(value, |value| value.to_string())
}

pub(crate) fn comma_separated<I, T>(values: I) -> String
where
    I: IntoIterator<Item = T>,
    T: ToString,
{
    values
        .into_iter()
        .map(|value| value.to_string())
        .collect::<Vec<_>>()
        .join(",")
}

pub(crate) fn spaced_hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len().saturating_mul(3));
    for (index, byte) in bytes.iter().enumerate() {
        use std::fmt::Write as _;
        if index != 0 {
            output.push(' ');
        }
        let _ = write!(output, "{byte:02x}");
    }
    output
}

pub(crate) fn output_timestamp_text(timestamp: output::capture::Timestamp) -> String {
    if timestamp.unix_seconds >= 0 || timestamp.nanoseconds == 0 {
        return format!("{}.{:09}", timestamp.unix_seconds, timestamp.nanoseconds);
    }

    // OutputTimestamp uses the canonical floor-seconds representation, so
    // (-3, 750_000_000) is -2.25 seconds rather than -3.75 seconds. Convert
    // that pair to conventional signed decimal notation for human output.
    let whole_seconds = -(timestamp.unix_seconds + 1);
    let fractional = 1_000_000_000 - timestamp.nanoseconds;
    format!("-{whole_seconds}.{fractional:09}")
}

pub(crate) fn emit_json(value: &impl Serialize) -> Result<(), CliError> {
    let rendered = serde_json::to_string_pretty(value)
        .map_err(|source| CliError::new(70, format!("serialize output failed: {source}")))?;
    write_machine_line(&rendered)
}

pub(crate) fn emit_json_compact(value: &impl Serialize) -> Result<(), CliError> {
    let rendered = serde_json::to_string(value)
        .map_err(|source| CliError::new(70, format!("serialize output failed: {source}")))?;
    write_machine_line(&rendered)
}
