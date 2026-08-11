// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use packetcraftr::{core, output};
use serde::Serialize;

use super::super::errors::CliError;
use super::machine::emit_json_compact;

pub(crate) fn emit_stream_record<T: Serialize>(
    command: output::contract::Command,
    sequence: &mut u64,
    result: T,
) -> Result<(), CliError> {
    emit_stream(command, *sequence, result, Vec::new())?;
    *sequence = next_stream_sequence(*sequence)?;
    Ok(())
}

pub(crate) fn emit_stream<T: Serialize>(
    command: output::contract::Command,
    sequence: u64,
    result: T,
    diagnostics: Vec<core::diagnostic::Diagnostic>,
) -> Result<(), CliError> {
    emit_json_compact(&output::envelope::Stream::success(
        command,
        sequence,
        result,
        diagnostics,
    ))
    .map_err(|error| error.at_sequence(sequence))
}

pub(crate) fn emit_stream_with_stats<T: Serialize>(
    command: output::contract::Command,
    sequence: u64,
    result: T,
    diagnostics: Vec<core::diagnostic::Diagnostic>,
    stats: output::envelope::Stats,
) -> Result<(), CliError> {
    emit_json_compact(
        &output::envelope::Stream::success(command, sequence, result, diagnostics)
            .with_stats(stats),
    )
    .map_err(|error| error.at_sequence(sequence))
}

/// Advances an NDJSON record sequence without allowing it to wrap.
pub(crate) fn next_stream_sequence(sequence: u64) -> Result<u64, CliError> {
    sequence.checked_add(1).ok_or_else(|| {
        CliError::classified(output::contract::Error::SequenceOverflow).at_sequence(sequence)
    })
}
