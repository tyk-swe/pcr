// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use bytes::Bytes;
use packetcraftr_core::frame::Frame;

use super::super::super::Packet;
use super::super::super::build::{DEFAULT_MAX_LAYERS, DEFAULT_MAX_PACKET_SIZE};
use super::super::super::diagnostic::Diagnostic;
use super::super::super::layout::PacketLayout;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecodeOptions {
    pub max_layers: usize,
    pub max_packet_size: usize,
    pub verify_checksums: bool,
}

impl Default for DecodeOptions {
    fn default() -> Self {
        Self {
            max_layers: DEFAULT_MAX_LAYERS,
            max_packet_size: DEFAULT_MAX_PACKET_SIZE,
            verify_checksums: true,
        }
    }
}

#[derive(Clone, Debug)]
pub struct DecodedPacket {
    pub packet: Packet,
    pub original: Bytes,
    pub frame: Frame,
    pub layout: PacketLayout,
    pub diagnostics: Vec<Diagnostic>,
}
