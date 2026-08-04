// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::path::PathBuf;

use clap::Args;

pub(super) const AFTER_LONG_HELP: &str = r#"When neither --hex nor --file is supplied, raw frame bytes are read from standard input.

With --filter, the dissection is emitted only when the frame matches; a frame that does not match emits nothing and the command still succeeds.

Examples:
  packetcraftr dissect --hex '45000014000000004001f6e7c0000201c6336402'
  packetcraftr --output json dissect --file frame.bin --link-type 1
  packetcraftr dissect --file frame.bin --filter 'icmpv4 && ip.dst == 198.51.100.2'"#;

#[derive(Debug, Args)]
pub(crate) struct DissectArgs {
    /// Whole-frame hexadecimal bytes.
    #[arg(long, conflicts_with = "file")]
    pub(crate) hex: Option<String>,
    /// File containing raw frame bytes.
    #[arg(long, value_name = "PATH", conflicts_with = "hex")]
    pub(crate) file: Option<PathBuf>,
    /// Open numeric DLT/link type (defaults to Ethernet/DLT 1).
    #[arg(long, default_value_t = 1)]
    pub(crate) link_type: u32,
    /// Emit the dissection only when the frame matches a display filter.
    #[arg(long, value_name = "EXPR")]
    pub(crate) filter: Option<String>,
}
