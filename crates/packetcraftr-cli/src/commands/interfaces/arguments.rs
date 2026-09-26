// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

pub(crate) const AFTER_LONG_HELP: &str = r"Examples:
  packetcraftr interfaces
  packetcraftr interfaces --interface lo
  packetcraftr --output json interfaces";

#[derive(Debug, clap::Args)]
pub(crate) struct Args {
    /// Only list the interface with this name or numeric index.
    #[arg(long, value_name = "NAME_OR_INDEX")]
    pub(crate) interface: Option<String>,
    /// List the packet timestamp types the capture backend advertises for each
    /// interface; types without a source are not selectable for capture.
    #[arg(long)]
    pub(crate) timestamp_types: bool,
}
