// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use serde::Serialize;

use packetcraftr_core::build::BuiltPacket;

use super::envelope::Published;
use super::frame::{Layout, Wire};

#[derive(Clone, Debug, Serialize)]
pub struct Report {
    /// Publishes the `bytes_hex` and `length` keys the contract declares,
    /// formatting the hexadecimal at serialization rather than retaining a
    /// second copy of the packet.
    #[serde(flatten)]
    pub frame: Wire,
    pub packet: packetcraftr_core::document::Packet,
    pub layout: Layout,
    pub requires_live_opt_in: bool,
}

/// A built packet, with the builder's diagnostics for the envelope.
impl From<BuiltPacket> for Published<Report> {
    fn from(built: BuiltPacket) -> Self {
        let requires_live_opt_in = packetcraftr::policy::requires_live_opt_in(&built);
        let BuiltPacket {
            bytes,
            packet,
            layout,
            diagnostics,
            ..
        } = built;
        Self::new(
            Report {
                frame: bytes.into(),
                packet: packetcraftr_core::document::Packet::from_packet(&packet),
                layout: layout.into(),
                requires_live_opt_in,
            },
            diagnostics,
        )
    }
}

/// One built packet in deterministic, zero-based Cartesian order.
#[derive(Clone, Debug, Serialize)]
pub struct PacketEvent {
    pub packet_index: u64,
    #[serde(flatten)]
    pub packet: Report,
}

/// The packet at a zero-based index in the expansion.
impl From<(u64, BuiltPacket)> for Published<PacketEvent> {
    fn from((packet_index, built): (u64, BuiltPacket)) -> Self {
        let Published {
            result: packet,
            diagnostics,
            stats,
        } = Published::<Report>::from(built);
        Self {
            result: PacketEvent {
                packet_index,
                packet,
            },
            diagnostics,
            stats,
        }
    }
}

impl super::stream::StreamRecord for PacketEvent {
    fn event_name(&self) -> &'static str {
        "packet"
    }
}

/// Totals published only after every packet has been built and emitted.
#[derive(Clone, Copy, Debug, Default, Serialize)]
pub struct Complete {
    pub packets_built: u64,
    pub bytes_built: u64,
}
