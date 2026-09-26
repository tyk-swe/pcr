// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! `rewrite`'s text output.

use crate::errors::CliError;
use crate::output;
use crate::rendering::write_plain_line;

pub(super) fn render_text(report: &output::rewrite::Report) -> Result<(), CliError> {
    if report.dry_run {
        write_plain_line(format_args!(
            "dry-run: {} of {} frames would change across {} interfaces; \
             {} changes reported, {} omitted",
            report.capture.frames_changed,
            report.capture.frames_read,
            report.capture.interfaces,
            report.changes.len(),
            report.changes_omitted
        ))
    } else {
        write_plain_line(format_args!(
            "rewrote {} of {} frames across {} interfaces into {}",
            report.capture.frames_changed,
            report.capture.frames_read,
            report.capture.interfaces,
            report.path
        ))
    }
}
