// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::IpAddr;

use bytes::Bytes;
use serde::{Deserialize, Serialize};

use crate::Packet;
use crate::diagnostic::Diagnostic;
use crate::layout::PacketLayout;

pub const DEFAULT_MAX_PACKET_SIZE: usize = 16 * 1024 * 1024;
pub const DEFAULT_MAX_LAYERS: usize = 64;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    #[default]
    Strict,
    Permissive,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Context {
    pub source: Option<IpAddr>,
    pub destination: Option<IpAddr>,
}

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
