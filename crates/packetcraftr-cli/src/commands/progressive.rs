// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use packetcraftr::{core, output};
use serde::Serialize;

use crate::errors::CliError;
use crate::rendering::NdjsonStream;

pub(crate) fn render_event<T: Serialize>(
    event: T,
    diagnostics: Vec<core::diagnostic::Diagnostic>,
    stream: &NdjsonStream,
) -> Result<(), CliError> {
    stream.emit_data(event, diagnostics)
}

pub(crate) fn render_complete<T: Serialize>(
    event: T,
    diagnostics: Vec<core::diagnostic::Diagnostic>,
    stats: output::envelope::Stats,
    stream: &NdjsonStream,
) -> Result<(), CliError> {
    stream.complete_with_stats(event, diagnostics, stats)
}
