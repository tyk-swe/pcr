// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use serde::Serialize;

use packetcraftr_core::build::BuiltPacket;

use super::envelope::Published;
use super::frame::{Layout, Wire};

#[derive(Clone, Debug, Serialize)]
pub struct Report {
    #[serde(flatten)]
    pub frame: Wire,
    pub packet: packetcraftr_core::document::Packet,
    pub layout: Layout,
    pub requires_live_opt_in: bool,
}

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

#[derive(Clone, Debug, Serialize)]
pub struct PacketEvent {
    pub packet_index: u64,
    #[serde(flatten)]
    pub packet: Report,
}

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

#[derive(Clone, Copy, Debug, Default, Serialize)]
pub struct Complete {
    pub packets_built: u64,
    pub bytes_built: u64,
}
