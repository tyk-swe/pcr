// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use clap::Args;

use crate::command_options::{CliBuildMode, RecipeArgs};

pub(crate) const AFTER_LONG_HELP: &str = r#"Examples:
  packetcraftr build --packet 'raw(text=hello)'
  packetcraftr --output raw build --packet-file packet.json"#;

#[derive(Debug, Args)]
pub(crate) struct BuildArgs {
    #[command(flatten)]
    pub(crate) recipe: RecipeArgs,
    /// Enforce protocol invariants or preserve explicitly permissive values.
    #[arg(long, value_enum, default_value_t = CliBuildMode::Strict)]
    pub(crate) mode: CliBuildMode,
}
