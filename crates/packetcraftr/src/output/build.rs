// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Structured `build` output.

use bytes::Bytes;
use serde::Serialize;

use packetcraftr_core::{
    build::Result as BuiltPacket, diagnostic::Diagnostic, document::Packet as PacketDocument,
    layout::Packet as PacketLayout,
};

use super::hex::compact_hex;

/// Structured result of `build`.
#[derive(Clone, Debug, Serialize)]
pub struct Result {
    #[serde(skip)]
    bytes: Bytes,
    pub bytes_hex: String,
    pub length: u64,
    pub packet: PacketDocument,
    pub layout: PacketLayout,
    pub requires_live_opt_in: bool,
}

impl Result {
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
                bytes_hex: compact_hex(&bytes),
                length: u64::try_from(bytes.len()).unwrap_or(u64::MAX),
                packet: PacketDocument::from_packet(&packet),
                layout,
                requires_live_opt_in,
                bytes,
            },
            diagnostics,
        )
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}
