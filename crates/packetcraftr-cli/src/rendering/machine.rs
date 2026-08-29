// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use packetcraftr::core::error::Kind;

use std::fmt;
use std::io::{self, Write};

use packetcraftr::{core, output};
use serde::Serialize;

use super::super::errors::CliError;

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

pub(crate) fn spaced_hex(bytes: &[u8]) -> impl fmt::Display + '_ {
    SpacedHex(bytes)
}

struct SpacedHex<'a>(&'a [u8]);

impl fmt::Display for SpacedHex<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (index, byte) in self.0.iter().enumerate() {
            if index != 0 {
                formatter.write_str(" ")?;
            }
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

pub(crate) fn captured_frame_text(frame: &output::frame::Captured) -> impl fmt::Display + '_ {
    CapturedFrameText(frame)
}

struct CapturedFrameText<'a>(&'a output::frame::Captured);

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

pub(crate) fn output_timestamp_text(timestamp: output::frame::Timestamp) -> String {
    if timestamp.unix_seconds >= 0 || timestamp.nanoseconds == 0 {
        return format!("{}.{:09}", timestamp.unix_seconds, timestamp.nanoseconds);
    }

    // OutputTimestamp uses the canonical floor-seconds representation, so
    // (-3, 750_000_000) is -2.25 seconds rather than -3.75 seconds. Convert
    // that pair to conventional signed decimal notation for human output.
    let whole_seconds = timestamp.unix_seconds.saturating_add(1).saturating_neg();
    let fractional = 1_000_000_000_u32.saturating_sub(timestamp.nanoseconds);
    format!("-{whole_seconds}.{fractional:09}")
}

pub(crate) fn emit_json(value: &impl Serialize) -> Result<(), CliError> {
    let stdout = io::stdout().lock();
    let mut writer = io::BufWriter::with_capacity(64 * 1024, stdout);
    serde_json::to_writer_pretty(&mut writer, value).map_err(json_error)?;
    writer
        .write_all(b"\n")
        .and_then(|()| writer.flush())
        .map_err(|source| CliError::new(Kind::Io, format!("write stdout failed: {source}")))
}

fn json_error(source: serde_json::Error) -> CliError {
    if source.is_io() {
        CliError::new(Kind::Io, format!("write stdout failed: {source}"))
    } else {
        CliError::new(Kind::Internal, format!("serialize output failed: {source}"))
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spaced_hex_is_lowercase_and_exact() {
        for (bytes, expected) in [
            (&[][..], ""),
            (&[0][..], "00"),
            (&[0, 10, 171, 255][..], "00 0a ab ff"),
        ] {
            assert_eq!(spaced_hex(bytes).to_string(), expected);
        }
    }

    #[test]
    fn timestamp_text_uses_conventional_signed_decimal_notation() {
        let cases = [
            ((3, 250_000_000), "3.250000000"),
            ((-3, 750_000_000), "-2.250000000"),
            ((-1, 999_999_999), "-0.000000001"),
            ((-3, 0), "-3.000000000"),
        ];

        for ((unix_seconds, nanoseconds), expected) in cases {
            let timestamp = output::frame::Timestamp {
                unix_seconds,
                nanoseconds,
            };
            assert_eq!(output_timestamp_text(timestamp), expected);
        }
    }
}
