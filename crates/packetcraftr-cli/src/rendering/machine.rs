// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::fmt;

use packetcraftr::{core, output};
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

pub(crate) fn captured_frame_text(frame: &output::capture::Frame) -> impl fmt::Display + '_ {
    CapturedFrameText(frame)
}

struct CapturedFrameText<'a>(&'a output::capture::Frame);

impl fmt::Display for CapturedFrameText<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let frame = self.0;
        write!(
            formatter,
            "dlt={} caplen={} wirelen={} {}",
            frame.link_type,
            frame.captured_length,
            frame.original_length,
            spaced_hex(frame.bytes())
        )
    }
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

pub(crate) fn emit_aggregate<T: Serialize>(
    command: output::contract::Command,
    result: T,
    diagnostics: Vec<core::diagnostic::Diagnostic>,
) -> Result<(), CliError> {
    emit_json(&output::envelope::Aggregate::success(
        command,
        result,
        diagnostics,
    ))
}

pub(crate) fn emit_aggregate_with_stats<T: Serialize>(
    command: output::contract::Command,
    result: T,
    diagnostics: Vec<core::diagnostic::Diagnostic>,
    stats: output::envelope::Stats,
) -> Result<(), CliError> {
    emit_json(&output::envelope::Aggregate::success(command, result, diagnostics).with_stats(stats))
}
