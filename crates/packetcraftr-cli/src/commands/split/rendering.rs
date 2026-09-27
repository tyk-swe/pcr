// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! `split`'s text output: one line per part, then the totals.

use crate::errors::CliError;
use crate::output;
use crate::rendering::{write_stdout_line, write_summary_line};

pub(super) fn render_text(report: &output::split::Report) -> Result<(), CliError> {
    for part in &report.files {
        let range = match (part.first_frame, part.last_frame) {
            (Some(first), Some(last)) if first == last => format!("frame {first}"),
            (Some(first), Some(last)) => format!("frames {first}-{last}"),
            _ => "no frames".to_owned(),
        };
        write_stdout_line(format_args!(
            "{}: {}, {} frames, {} decoded bytes, {} encoded bytes",
            part.file, range, part.frames, part.decoded_bytes, part.encoded_bytes
        ))?;
    }
    write_summary_line(format_args!(
        "split {} file(s) under {}: {} frames, {} decoded bytes, {} encoded bytes; metadata describes the source capture",
        report.files.len(),
        report.directory,
        report.frames_read,
        report.decoded_bytes_written,
        report.encoded_bytes_written
    ))
}
