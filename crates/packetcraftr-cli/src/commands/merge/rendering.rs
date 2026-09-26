// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! `merge`'s text output.

use crate::errors::CliError;
use crate::output;
use crate::rendering::write_summary_line;

pub(super) fn render_text(report: &output::merge::Report) -> Result<(), CliError> {
    write_summary_line(format_args!(
        "merged {} frames ({} bytes) across {} interfaces into {}",
        report.frames,
        report.captured_bytes,
        report.interfaces.len(),
        report.path
    ))
}
