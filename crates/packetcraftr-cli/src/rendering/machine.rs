// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use packetcraftr::core::error::Kind;

use std::io::{self, Write};

use packetcraftr::{core, output};
use serde::Serialize;

use crate::errors::CliError;

pub(crate) fn emit_json(value: &impl Serialize) -> Result<(), CliError> {
    let stdout = io::stdout().lock();
    let mut writer = io::BufWriter::with_capacity(64 * 1024, stdout);
    serde_json::to_writer_pretty(&mut writer, value).map_err(json_error)?;
    writer
        .write_all(b"\n")
        .and_then(|()| writer.flush())
        .map_err(|source| CliError::new(Kind::Io, format!("write stdout failed: {source}")))
}

fn json_error(source: serde_json::Error) -> CliError {
    if source.is_io() {
        CliError::new(Kind::Io, format!("write stdout failed: {source}"))
    } else {
        CliError::new(Kind::Internal, format!("serialize output failed: {source}"))
    }
}

pub(crate) fn emit_aggregate<T: Serialize>(
    command: output::contract::Command,
    result: T,
    diagnostics: Vec<core::diagnostic::Diagnostic>,
) -> Result<(), CliError> {
    emit_json(&output::envelope::Envelope::success(
        command,
        result,
        diagnostics,
    ))
}

pub(crate) fn emit_aggregate_with_stats<T: Serialize>(
    command: output::contract::Command,
    result: T,
    diagnostics: Vec<core::diagnostic::Diagnostic>,
    stats: output::envelope::Stats,
) -> Result<(), CliError> {
    emit_json(&output::envelope::Envelope::success(command, result, diagnostics).with_stats(stats))
}
