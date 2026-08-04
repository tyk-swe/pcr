// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use clap::Args;

pub(super) const AFTER_LONG_HELP: &str = r#"Examples:
  packetcraftr protocols
  packetcraftr protocols ipv4
  packetcraftr --output json protocols IP4"#;

#[derive(Debug, Args)]
pub(crate) struct ProtocolsArgs {
    /// Built-in protocol name or alias to describe.
    #[arg(value_name = "PROTOCOL")]
    pub(crate) protocol: Option<String>,
}
