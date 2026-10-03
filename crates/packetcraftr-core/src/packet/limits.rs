// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::Error;

/// The default [`Limits::max_packet_size`].
pub const DEFAULT_MAX_PACKET_SIZE: usize = 16 * 1024 * 1024;
/// The default [`Limits::max_layers`].
pub const DEFAULT_MAX_LAYERS: usize = 64;

/// Every value is honored as given, and zero refuses every packet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    pub max_layers: usize,
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

impl Limits {
    /// Always succeeds; it exists so every limits type validates the same way.
    pub const fn validate(&self) -> Result<(), Error> {
        Ok(())
    }
}
