// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! `replay`'s text output.

use crate::errors::CliError;
use crate::output;
use crate::rendering::{spaced_hex, write_summary_line};

/// One transmitted frame: where it went and its exact bytes.
pub(super) fn frame_line(frame: &output::replay::Frame) -> String {
    format!(
        "{}: sent {} bytes via {} (index {}, {}) dlt={} {}",
        frame.source_index,
        frame.bytes_sent,
        frame.interface.name,
        frame.interface.index,
        frame.link_mode,
        frame.frame.link_type,
        spaced_hex(frame.frame.bytes())
    )
}

/// The closing line; a filtered replay also names how many frames it read.
pub(super) fn render_summary(
    report: &packetcraftr::replay::Report,
    filtered: bool,
) -> Result<(), CliError> {
    if filtered {
        write_summary_line(format_args!(
            "replayed {} of {} frame(s), {} byte(s), scheduled delay {:?}",
            report.frames_transmitted,
            report.frames_read,
            report.bytes_transmitted,
            report.scheduled_duration
        ))
    } else {
        write_summary_line(format_args!(
            "replayed {} frame(s), {} byte(s), scheduled delay {:?}",
            report.frames_transmitted, report.bytes_transmitted, report.scheduled_duration
        ))
    }
}
