// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Structured `build` output.

use serde::Serialize;

use packetcraftr_core::{build::BuiltPacket, diagnostic::Diagnostic, layout::PacketLayout};

use super::frame::Wire;

/// Structured result of `build`.
#[derive(Clone, Debug, Serialize)]
pub struct Report {
    /// Publishes the `bytes_hex` and `length` keys the contract declares,
    /// formatting the hexadecimal at serialization rather than retaining a
    /// second copy of the packet.
    #[serde(flatten)]
    pub frame: Wire,
    pub packet: packetcraftr_core::document::Packet,
    pub layout: PacketLayout,
    pub requires_live_opt_in: bool,
}

impl Report {
    pub fn from_built(built: BuiltPacket) -> (Self, Vec<Diagnostic>) {
        let BuiltPacket {
            bytes,
            packet,
            layout,
            diagnostics,
            requires_live_opt_in,
        } = built;
        (
            Self {
                frame: Wire::new(bytes),
                packet: packetcraftr_core::document::Packet::from_packet(&packet),
                layout,
                requires_live_opt_in,
            },
            diagnostics,
        )
    }
}
