// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! `export`'s text output.

use crate::errors::CliError;
use crate::output;
use crate::rendering::write_summary_line;

pub(super) fn render_text(report: &output::export::Report) -> Result<(), CliError> {
    write_summary_line(format_args!(
        "exported {} of {} physical frames to {}; {} complete and {} incomplete datagrams, {} unmatched stream selectors, {} unmatched datagram selectors",
        report.capture.frames_selected,
        report.capture.frames_read,
        report.path,
        report.selected_complete_datagrams,
        report.selected_incomplete_datagrams.len(),
        report.unmatched_streams.len(),
        report.unmatched_datagram_frames.len()
    ))
}
