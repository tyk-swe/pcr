// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::io::{Read, Write};

use packetcraftr_core::capture_file::{self as capture, NormalizeOptions, NormalizeReport, Reader};

use super::selection::Selection;
use crate::command_options::OfflineCaptureLimits;
use crate::errors::CliError;

pub(super) fn run(
    reader: &mut Reader<impl Read>,
    limits: OfflineCaptureLimits,
    selection: Selection<'_>,
    format: capture::Format,
    destination: impl Write,
) -> Result<NormalizeReport, CliError> {
    let options = NormalizeOptions {
        max_size: limits.reader_bounds().max_frame_bytes,
        max_interfaces: limits.reader_bounds().max_interfaces,
        stream_limits: limits.stream_limits(),
    };
    let (_, report) = capture::normalize(reader, destination, format, options, |number, frame| {
        selection
            .matches(number, frame)
            .map_err(CliError::into_boundary_error)
    })
    .map_err(CliError::classified)?;
    Ok(report)
}
