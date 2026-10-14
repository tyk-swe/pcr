// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::errors::CliError;
use crate::output;
use crate::rendering::{duration_text, spaced_hex, write_summary_line};

pub(super) fn frame_line(
    frame: &output::replay::Frame,
    presentation: crate::rendering::Presentation,
) -> String {
    format!(
        "{}: sent {} bytes via {} (index {}, {}) dlt={} {}",
        frame.source_index,
        frame.bytes_sent,
        frame.interface.name,
        frame.interface.index,
        frame.link_mode,
        frame.frame.link_type,
        if presentation.verbose {
            spaced_hex(frame.frame.bytes()).to_string()
        } else {
            String::new()
        }
    )
}

pub(super) fn render_summary(
    report: &packetcraftr::replay::Report,
    filtered: bool,
) -> Result<(), CliError> {
    if filtered {
        write_summary_line(format_args!(
            "replayed {} of {} frame(s), {} byte(s), scheduled delay {}",
            report.frames_transmitted,
            report.frames_read,
            report.bytes_transmitted,
            duration_text(report.scheduled_duration)
        ))
    } else {
        write_summary_line(format_args!(
            "replayed {} frame(s), {} byte(s), scheduled delay {}",
            report.frames_transmitted,
            report.bytes_transmitted,
            duration_text(report.scheduled_duration)
        ))
    }
}
