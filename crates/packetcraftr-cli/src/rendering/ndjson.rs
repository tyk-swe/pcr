// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use packetcraftr::{core, output};
use serde::Serialize;

use super::super::errors::CliError;
use super::machine::emit_json_compact;

pub(crate) fn emit_next<T: Serialize>(
    command: output::contract::Command,
    sequence: &mut u64,
    result: T,
) -> Result<(), CliError> {
    emit(command, *sequence, result, Vec::new())?;
    *sequence = next_sequence(*sequence)?;
    Ok(())
}

pub(crate) fn emit<T: Serialize>(
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

pub(crate) fn emit_with_stats<T: Serialize>(
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
fn next_sequence(sequence: u64) -> Result<u64, CliError> {
    sequence.checked_add(1).ok_or_else(|| {
        CliError::classified(output::contract::Error::SequenceOverflow).at_sequence(sequence)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stream_sequence_advances_until_the_contract_limit() {
        assert_eq!(next_sequence(0).expect("zero can advance"), 1);
        assert_eq!(
            next_sequence(u64::MAX - 1).expect("penultimate value can advance"),
            u64::MAX,
        );

        let error = next_sequence(u64::MAX).expect_err("maximum must not wrap");
        assert_eq!(error.exit_code, 70);
        assert_eq!(error.classification.code, "internal.output_sequence");
        assert_eq!(error.sequence, Some(u64::MAX));
    }

    #[test]
    fn stream_sequence_increments_one_record_at_a_time() {
        let mut sequence = 0;
        for expected in 1..=4 {
            sequence = next_sequence(sequence).expect("small sequence increments");
            assert_eq!(sequence, expected);
        }
    }
}
