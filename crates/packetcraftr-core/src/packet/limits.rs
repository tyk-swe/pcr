// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::layout::{DEFAULT_MAX_LAYERS, DEFAULT_MAX_PACKET_SIZE};

/// Ceilings on one packet, shared by decoding
/// ([`decode::Options`](crate::decode::Options)) and building
/// ([`build::Options`](crate::build::Options)).
///
/// Every value is honored as given: a packet with more layers or bytes than
/// its ceiling is refused where it is decoded or built, and zero refuses
/// every packet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    /// Protocol layers in one packet.
    pub max_layers: usize,
    /// Bytes in one packet, encoded or decoded.
    pub max_packet_size: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_layers: DEFAULT_MAX_LAYERS,
            max_packet_size: DEFAULT_MAX_PACKET_SIZE,
        }
    }
}
