// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::build::{DEFAULT_MAX_LAYERS, DEFAULT_MAX_PACKET_SIZE};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Options {
    pub max_layers: usize,
    pub max_packet_size: usize,
    pub verify_checksums: bool,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            max_layers: DEFAULT_MAX_LAYERS,
            max_packet_size: DEFAULT_MAX_PACKET_SIZE,
            verify_checksums: true,
        }
    }
}
