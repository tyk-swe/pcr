// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

pub(crate) const AFTER_LONG_HELP: &str = r"Examples:
  packetcraftr routes
  packetcraftr routes --all
  packetcraftr --output json routes";

#[derive(Debug, clap::Args)]
pub(crate) struct Args {
    /// Report all interfaces with a usable MTU, including ones that are not up.
    #[arg(long)]
    pub(crate) all: bool,
}
