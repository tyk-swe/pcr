// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::command_options::{BuildMode, PacketBudgetArgs, RecipeArgs};

pub(crate) const AFTER_LONG_HELP: &str = r#"Examples:
  packetcraftr build --packet 'raw(text=hello)'
  packetcraftr --output raw build --packet-file packet.json"#;

#[derive(Debug, clap::Args)]
pub(crate) struct Args {
    #[command(flatten)]
    pub(crate) recipe: RecipeArgs,
    /// Enforce protocol invariants or preserve explicitly permissive values.
    #[arg(long, value_enum, default_value_t = BuildMode::Strict)]
    pub(crate) mode: BuildMode,
    #[command(flatten)]
    pub(crate) budget: PacketBudgetArgs,
}
