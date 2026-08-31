// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use bytes::Bytes;

use crate::Packet;
use crate::codec::Mode;
use crate::diagnostic::Diagnostic;
use crate::layout::{DEFAULT_MAX_LAYERS, DEFAULT_MAX_PACKET_SIZE, PacketLayout};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Options {
    pub mode: Mode,
    pub max_layers: usize,
    pub max_packet_size: usize,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            mode: Mode::Strict,
            max_layers: DEFAULT_MAX_LAYERS,
            max_packet_size: DEFAULT_MAX_PACKET_SIZE,
        }
    }
}

/// Exact encoded bytes plus the resolved packet, byte layout, and diagnostics.
#[derive(Clone, Debug)]
pub struct BuiltPacket {
    pub bytes: Bytes,
    pub packet: Packet,
    pub layout: PacketLayout,
    pub diagnostics: Vec<Diagnostic>,
    /// Live transmission must explicitly opt in when this is true.
    pub requires_live_opt_in: bool,
}
