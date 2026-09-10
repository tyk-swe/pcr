// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::command_options::{BuildMode, PacketBudgetArgs, RecipeArgs, TemplateArgs};

pub(crate) const AFTER_LONG_HELP: &str = r#"Examples:
  packetcraftr build --packet 'raw(text=hello)'
  packetcraftr --output raw build --packet-file packet.json
  packetcraftr --output ndjson build --packet 'ipv4(dst=192.0.2.1)/udp()' --axis '0.ttl=[1,64]' --axis '1.dport=[53,5353]'

Packet sets use Cartesian order with the last axis varying fastest. Text and hex
emit one packet at a time. NDJSON emits packet events and one complete event;
errors may follow already emitted packets. JSON and raw require exactly one packet."#;

#[derive(Debug, clap::Args)]
pub(crate) struct Args {
    #[command(flatten)]
    pub(crate) recipe: RecipeArgs,
    #[command(flatten)]
    pub(crate) template: TemplateArgs,
    /// Enforce protocol invariants or preserve explicitly permissive values.
    #[arg(long, value_enum, default_value_t = BuildMode::Strict)]
    pub(crate) mode: BuildMode,
    #[command(flatten)]
    pub(crate) budget: PacketBudgetArgs,
}
