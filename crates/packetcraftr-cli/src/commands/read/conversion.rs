// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use packetcraftr::core;

/// Decode bounds use the accepted per-frame capture limit, not the smaller
/// dissector default.
pub(super) fn decode_options(max_frame_bytes: usize) -> core::decode::Options {
    core::decode::Options {
        max_packet_size: max_frame_bytes,
        ..core::decode::Options::default()
    }
}
