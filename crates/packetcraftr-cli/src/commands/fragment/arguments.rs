// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::command_options::{PacketBudgetArgs, RecipeArgs};

#[derive(Debug, clap::Args)]
pub(crate) struct Args {
    /// Compress binary capture output; independent of the input's detected format.
    #[arg(long, value_enum, default_value_t = crate::command_options::Compression::None)]
    pub(crate) compression: crate::command_options::Compression,

    #[command(flatten)]
    pub(crate) recipe: RecipeArgs,
    /// IP MTU, excluding the link header. Fragmentation is always explicit.
    #[arg(long)]
    pub(crate) mtu: usize,
    /// Fragment identification; required when splitting IPv6.
    #[arg(long)]
    pub(crate) identification: Option<u32>,
    /// Maximum fragments produced from the datagram; at most 8192.
    #[arg(long, default_value_t = 1024)]
    pub(crate) max_fragments: usize,
    /// Maximum bytes across all produced fragment frames.
    #[arg(long, default_value_t = 256 * 1024 * 1024)]
    pub(crate) max_output_bytes: usize,
    #[command(flatten)]
    pub(crate) budget: PacketBudgetArgs,
}
