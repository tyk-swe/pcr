// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::path::PathBuf;

use packetcraftr_core::frame::LinkType;

use crate::command_options::{DecodeArgs, PacketBudgetArgs, TreeArgs, link_type};

pub(crate) const AFTER_LONG_HELP: &str = r"Reads raw bytes from stdin when none of --hex, --hex-file, or --file is given.
Hex input accepts an optional 0x prefix and whitespace, colon, or dash separators.
With --filter, non-matching frames emit nothing in text/hex/raw (noting the miss
on stderr) and emit `matched: false, dissection: null` in JSON.

Examples:
  packetcraftr packet dissect --link-type 228 --hex '4500001c0000000040018eaac0000201c63364020800f7ff00000000'
  packetcraftr --output json packet dissect --file frame.bin --link-type 1
  packetcraftr packet dissect --file frame.bin --filter 'icmpv4 && ip.dst == 198.51.100.2'
  packetcraftr --output hex packet build --packet 'ipv4()/icmpv4(identifier=1)' | packetcraftr packet dissect --link-type ipv4 --hex -
  packetcraftr packet dissect --hex-file frame.txt --link-type ipv4 --tree

See `packetcraftr reference topics filters` for the --filter language.";

#[derive(Debug, clap::Args)]
pub(crate) struct Args {
    /// Select a registered field; repeat to preserve the requested column order.
    #[arg(long = "field", value_name = "PATH", conflicts_with = "tree")]
    pub(crate) fields: Vec<String>,
    /// Maximum encoded projection data bytes across all rows (excluding envelopes).
    #[arg(long, default_value_t = 16 * 1024 * 1024)]
    pub(crate) max_projection_bytes: usize,

    /// Whole-frame hexadecimal bytes; - reads hexadecimal text from redirected stdin.
    #[arg(long, value_name = "HEX|-", conflicts_with_all = ["file", "hex_file"])]
    pub(crate) hex: Option<String>,
    /// File containing hexadecimal text for the whole frame.
    #[arg(long, value_name = "PATH", conflicts_with_all = ["hex", "file"])]
    pub(crate) hex_file: Option<PathBuf>,
    /// File containing raw frame bytes.
    #[arg(long, value_name = "PATH", conflicts_with_all = ["hex", "hex_file"])]
    pub(crate) file: Option<PathBuf>,
    #[arg(
        long,
        value_name = "NAME|NUMBER",
        value_parser = link_type::parse,
        default_value = "1",
        help = concat!(
            "Link type of the input frame, ",
            link_type::names_help!(),
            ". Defaults to Ethernet (1).",
        ),
    )]
    pub(crate) link_type: LinkType,
    /// Filter the decoded frame; aggregate JSON reports whether it matched.
    #[arg(long, value_name = "EXPR")]
    pub(crate) filter: Option<String>,
    #[command(flatten)]
    pub(crate) tree: TreeArgs,
    #[command(flatten)]
    pub(crate) decode: DecodeArgs,
    #[command(flatten)]
    pub(crate) budget: PacketBudgetArgs,
}
