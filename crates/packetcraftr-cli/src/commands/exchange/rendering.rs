// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use packetcraftr_core::analysis::pcap::Format;

use packetcraftr_cli::output;

use crate::errors::CliError;
use crate::rendering::{render_diagnostics_text, write_capture_file, write_stdout_line};

pub(super) fn render_text(
    converted: &output::workflow::Converted<output::exchange::Report>,
) -> Result<(), CliError> {
    let result = &converted.result;
    write_stdout_line(format_args!(
        "sent={} responses={} unanswered={} unsolicited={} undecoded={} bytes={}",
        result.sent.len(),
        result.responses.len(),
        result.unanswered.len(),
        result.unsolicited.len(),
        result.undecoded.len(),
        converted
            .stats
            .as_ref()
            .expect("exchange conversion includes packet statistics")
            .bytes
    ))?;
    render_diagnostics_text(&converted.diagnostics)
}

pub(super) fn render_capture(
    result: &output::exchange::Report,
    format: Format,
    compression: crate::command_options::Compression,
) -> Result<(), CliError> {
    write_capture_file(format, result.capture_frames().iter().cloned(), compression)
}
