// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use packetcraftr::packet;

/// Advances a counter, reporting overflow as a sequence-overflow contract error.
pub(super) fn next_frame_number(value: u64, sequence: u64) -> Result<u64, crate::errors::CliError> {
    value.checked_add(1).ok_or_else(|| {
        crate::errors::CliError::classified(packetcraftr::output::contract::Error::SequenceOverflow)
            .at_sequence(sequence)
    })
}

/// Decode bounds derived from the operator's per-frame capture limit.
///
/// The reader already accepted the frame at this size, so the dissector must
/// not then refuse it at its own smaller default.
pub(super) fn decode_options(max_frame_bytes: usize) -> packet::decode::Options {
    packet::decode::Options {
        max_packet_size: max_frame_bytes,
        ..packet::decode::Options::default()
    }
}
