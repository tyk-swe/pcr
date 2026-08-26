// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

pub(crate) const AFTER_LONG_HELP: &str = r#"Examples:
  packetcraftr protocols
  packetcraftr protocols ipv4
  packetcraftr protocols ipv4 --example
  packetcraftr --output json protocols IP4"#;

#[derive(Debug, clap::Args)]
pub(crate) struct Args {
    /// Built-in protocol name or alias to describe.
    #[arg(value_name = "PROTOCOL")]
    pub(crate) protocol: Option<String>,
    /// Print a minimal v2 YAML layer example for this protocol.
    #[arg(long)]
    pub(crate) example: bool,
}
