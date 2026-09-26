// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Captured-frame text shared by every command that prints frames.

use std::fmt;

use crate::errors::CliError;
use crate::output;

use super::{render_diagnostics_text, render_dns_records, spaced_hex, write_stdout_line};

/// One frame line for text output, with the dissected stack and its
/// diagnostics when the command decoded the frame.
pub(crate) fn render_frame_text(
    source_frame: output::frame::SourceFrame,
    frame: &output::frame::Captured,
    decoded: Option<&output::frame::Stack>,
) -> Result<(), CliError> {
    match decoded {
        None => write_stdout_line(format_args!(
            "{source_frame}: {}",
            captured_frame_text(frame)
        )),
        Some(decoded) => {
            write_stdout_line(format_args!(
                "{source_frame}: dlt={} caplen={} wirelen={} layers={} {}",
                frame.link_type,
                frame.captured_length,
                frame.original_length,
                decoded
                    .packet
                    .layers
                    .iter()
                    .map(|layer| layer.protocol.as_str())
                    .collect::<Vec<_>>()
                    .join("/"),
                spaced_hex(frame.bytes())
            ))?;
            render_dns_records(&decoded.packet)?;
            if !decoded.diagnostics.is_empty() {
                write_stdout_line(format_args!("{source_frame}: diagnostics:"))?;
                render_diagnostics_text(&decoded.diagnostics)?;
            }
            Ok(())
        }
    }
}

/// Renders `undecoded [<label> ]{captured_frame_text(frame)}` for every row,
/// so the section's format string lives here alone while each command keeps
/// its own row type.
pub(crate) fn render_undecoded<'a>(
    rows: impl IntoIterator<Item = (Option<String>, &'a output::frame::Captured)>,
) -> Result<(), CliError> {
    for (label, frame) in rows {
        match label {
            Some(label) => write_stdout_line(format_args!(
                "undecoded {label} {}",
                captured_frame_text(frame)
            ))?,
            None => write_stdout_line(format_args!("undecoded {}", captured_frame_text(frame)))?,
        }
    }
    Ok(())
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
