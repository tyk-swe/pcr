// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Structured `dissect` output.

use serde::Serialize;

use packetcraftr_core::{decode::DecodedPacket, diagnostic::Diagnostic, layout::PacketLayout};

use super::frame::Wire;

/// Structured result of `dissect`.
#[derive(Clone, Debug, Serialize)]
pub struct Report {
    /// Publishes the `bytes_hex` and `length` keys the contract declares,
    /// formatting the hexadecimal at serialization rather than retaining a
    /// second copy of the frame.
    #[serde(flatten)]
    pub frame: Wire,
    pub link_type: u32,
    pub packet: packetcraftr_core::document::Packet,
    pub layout: PacketLayout,
}

impl Report {
    pub fn from_decoded(decoded: DecodedPacket) -> (Self, Vec<Diagnostic>) {
        let DecodedPacket {
            packet,
            original,
            frame,
            layout,
            diagnostics,
        } = decoded;
        (
            Self {
                frame: Wire::new(original),
                link_type: frame.link_type.0,
                packet: packetcraftr_core::document::Packet::from_packet(&packet),
                layout,
            },
            diagnostics,
        )
    }
}

/// What `dissect` publishes once a filter has decided: the dissection when the
/// frame matched, and an explicit `null` when it did not.
#[derive(Clone, Debug, Serialize)]
pub struct AggregateResult {
    matched: bool,
    dissection: Option<Report>,
}

impl AggregateResult {
    #[must_use]
    pub const fn new(dissection: Option<Report>) -> Self {
        Self {
            matched: dissection.is_some(),
            dissection,
        }
    }
}
