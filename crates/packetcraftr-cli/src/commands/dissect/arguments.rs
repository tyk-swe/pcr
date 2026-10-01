// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::path::PathBuf;

use packetcraftr_core::frame::LinkType;

use crate::command_options::{DecodeArgs, PacketBudgetArgs, TreeArgs, link_type};

pub(crate) const AFTER_LONG_HELP: &str = r"When none of --hex, --hex-file, or --file is supplied, raw frame bytes are read from standard input.

Hexadecimal text comes from --hex VALUE, from redirected stdin with --hex -, or from a file with --hex-file. It may carry a 0x prefix and whitespace, colon, or dash separators, so `packetcraftr --output hex build ...` pipes straight in. The text is read through a bound derived from --max-packet-size, and the decoded bytes must also fit it.

--tree prints each layer's header line followed by its fields as an indented tree, in text output only. Bytes print as lowercase hex with their count, malformed layers show their preserved bytes, and (derived) marks fields the protocol schema defines as derivable, such as lengths and checksums; values are always the decoded wire values. All tree text is terminal-escaped and counts against --max-tree-bytes.

With --filter, text, hex, and raw output emit the dissection only when the frame matches; when the frame does not match, stdout stays empty (still a success) and `frame did not match the filter` is reported on stderr. Aggregate JSON always emits one document: result.matched reports the filter outcome and result.dissection is null only when the frame does not match.

Examples:
  packetcraftr dissect --link-type 228 --hex '4500001c0000000040018eaac0000201c63364020800f7ff00000000'
  packetcraftr --output json dissect --file frame.bin --link-type 1
  packetcraftr dissect --file frame.bin --filter 'icmpv4 && ip.dst == 198.51.100.2'
  packetcraftr dissect --file frame.bin --link-type 228 --tls-port 4433
  packetcraftr --output hex build --packet 'ipv4()/icmpv4(identifier=1)' | packetcraftr dissect --link-type ipv4 --hex -
  packetcraftr dissect --hex-file frame.txt --link-type ipv4 --tree

See `packetcraftr topics filters` for the --filter language.";

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
