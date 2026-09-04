// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use clap::Args;
use packetcraftr::core;

/// The finite layer and byte budgets `build` and `dissect` apply to one
/// packet, shared so both commands spell the same flags with the same
/// defaults.
#[derive(Clone, Copy, Debug, Args)]
pub(crate) struct PacketBudgetArgs {
    /// Maximum protocol layers accepted in one packet.
    #[arg(long, value_name = "N", default_value_t = core::layout::DEFAULT_MAX_LAYERS)]
    pub(crate) max_layers: usize,
    /// Maximum packet bytes accepted, encoded or decoded.
    #[arg(long, value_name = "BYTES", default_value_t = core::layout::DEFAULT_MAX_PACKET_SIZE)]
    pub(crate) max_packet_size: usize,
}

impl PacketBudgetArgs {
    pub(crate) fn build_options(self, mode: core::codec::Mode) -> core::build::Options {
        core::build::Options {
            mode,
            max_layers: self.max_layers,
            max_packet_size: self.max_packet_size,
        }
    }

    pub(crate) fn decode_options(self) -> core::decode::Options {
        core::decode::Options {
            max_layers: self.max_layers,
            max_packet_size: self.max_packet_size,
        }
    }
}
