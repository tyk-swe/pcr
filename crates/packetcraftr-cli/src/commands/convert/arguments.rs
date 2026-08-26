// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::path::PathBuf;

pub(crate) const AFTER_LONG_HELP: &str = r#"Examples:
  packetcraftr convert examples/documents/packet-ipv4-udp.json
  packetcraftr convert --check examples/documents/
  packetcraftr convert --stdout - < packet.json"#;

#[derive(Debug, clap::Args)]
pub(crate) struct Args {
    /// Target schema version to convert to.
    #[arg(long, default_value = "packet/v2", value_name = "SCHEMA")]
    pub(crate) to: String,

    /// Check if files need conversion without writing changes.
    #[arg(long)]
    pub(crate) check: bool,

    /// Print converted document to stdout instead of rewriting files in place.
    #[arg(long)]
    pub(crate) stdout: bool,

    /// Paths to files or directories to convert, or - for stdin.
    #[arg(required = true, value_name = "PATHS")]
    pub(crate) paths: Vec<PathBuf>,
}
