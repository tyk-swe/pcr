// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::path::PathBuf;

use crate::command_options::TlsPortArgs;

pub(crate) const AFTER_LONG_HELP: &str = r#"When neither --hex nor --file is supplied, raw frame bytes are read from standard input.

With --filter, text, hex, raw, and document output emit the dissection only when the frame matches. Aggregate JSON always emits one document: result.matched reports the filter outcome and result.dissection is null only when the frame does not match.

Examples:
  packetcraftr dissect --hex '45000014000000004001f6e7c0000201c6336402'
  packetcraftr --output document dissect --hex '45000014000000004001f6e7c0000201c6336402'
  packetcraftr --output json dissect --file frame.bin --link-type 1
  packetcraftr dissect --file frame.bin --filter 'icmpv4 && ip.dst == 198.51.100.2'
  packetcraftr dissect --file frame.bin --link-type 228 --tls-port 4433"#;

#[derive(Debug, clap::Args)]
pub(crate) struct Args {
    /// Whole-frame hexadecimal bytes.
    #[arg(long, conflicts_with = "file")]
    pub(crate) hex: Option<String>,
    /// File containing raw frame bytes.
    #[arg(long, value_name = "PATH", conflicts_with = "hex")]
    pub(crate) file: Option<PathBuf>,
    /// Open numeric DLT/link type (defaults to Ethernet/DLT 1).
    #[arg(long, default_value_t = 1)]
    pub(crate) link_type: u32,
    /// Filter the decoded frame; aggregate JSON reports whether it matched.
    #[arg(long, value_name = "EXPR")]
    pub(crate) filter: Option<String>,
    /// Emit every field in document output, skipping minimization.
    #[arg(long)]
    pub(crate) full: bool,
    #[command(flatten)]
    pub(crate) tls_ports: TlsPortArgs,
}
