// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

pub(crate) const AFTER_LONG_HELP: &str = r"Without NAME, lists the topics. Topics print text only and need no capture, network, or privileges.

Examples:
  packetcraftr topics
  packetcraftr topics expressions
  packetcraftr topics filters
  packetcraftr topics formats
  packetcraftr topics exit-codes";

#[derive(Debug, clap::Args)]
pub(crate) struct Args {
    /// Topic to print: expressions, filters, formats, or exit-codes. Omit to list them.
    #[arg(value_name = "NAME")]
    pub(crate) name: Option<String>,
}
