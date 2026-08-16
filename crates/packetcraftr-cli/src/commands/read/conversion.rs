// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use packetcraftr::core;

/// Advances a counter, reporting overflow as a sequence-overflow contract error.
pub(super) fn next_frame_number(value: u64, sequence: u64) -> Result<u64, crate::errors::CliError> {
    value.checked_add(1).ok_or_else(|| {
        crate::errors::CliError::classified(packetcraftr::output::contract::Error::SequenceOverflow)
            .at_sequence(sequence)
    })
}

/// Decode bounds use the accepted per-frame capture limit, not the smaller
/// dissector default.
pub(super) fn decode_options(max_frame_bytes: usize) -> core::decode::DecodeOptions {
    core::decode::DecodeOptions {
        max_packet_size: max_frame_bytes,
        ..core::decode::DecodeOptions::default()
    }
}
