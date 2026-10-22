// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::capture_output::CaptureOutputArgs;
use super::session::SessionArgs;
use crate::command_options::{BuildMode, PacketBudgetArgs, RecipeArgs, TemplateArgs};

pub(crate) const AFTER_LONG_HELP: &str = r"Examples:
  packetcraftr packet build --packet 'raw(text=hello)'
  packetcraftr --output raw packet build --packet-file packet.json
  packetcraftr --output ndjson packet build --packet 'ipv4(dst=192.0.2.1)/udp()' --axis '0.ttl=[1,64]' --axis '1.dport=[53,5353]'
  packetcraftr packet build --packet-file vlan.json --set ipv4.ttl=5 --set udp.destination_port=53
  packetcraftr --output pcapng packet build --packet 'ipv4()/icmpv4(identifier=1)' --link-type ipv4 > packet.pcapng
  packetcraftr --output pcap packet build --session tcp --packet 'ethernet()/ipv4(src=192.0.2.1,dst=192.0.2.2)/tcp(dport=80)/raw(text=ping)' --link-type ethernet --session-response-file reply.bin > conversation.pcap

Packet sets expand in Cartesian order (last axis varies fastest); JSON and raw
require a single packet. PCAP/PCAPNG output requires --link-type matching the
first layer. --session expands a deterministic TCP or UDP conversation spaced
by --session-step-ns from --timestamp.

See `packetcraftr reference topics expressions` and `packetcraftr reference topics filters`.";

#[derive(Debug, clap::Args)]
pub(crate) struct Args {
    #[command(flatten)]
    pub(crate) recipe: RecipeArgs,
    /// Override one recipe field before axes expand, e.g. ipv4.ttl=5 or
    /// ipv4#2.ttl=9. The selector is <protocol>[#occurrence].<field> or a
    /// zero-based LAYER.FIELD, and the value follows packet-expression syntax.
    /// Repeat up to 64 times; a later override of the same field wins.
    #[arg(long = "set", value_name = "SELECTOR=VALUE")]
    #[allow(
        rustdoc::invalid_html_tags,
        reason = "clap prints this doc comment verbatim as --help text; it is not rustdoc markup"
    )]
    pub(crate) set: Vec<String>,
    #[command(flatten)]
    pub(crate) template: TemplateArgs,
    #[command(flatten)]
    pub(crate) session: SessionArgs,
    /// Enforce protocol invariants or preserve explicitly permissive values.
    #[arg(long, value_enum, default_value_t = BuildMode::Strict)]
    pub(crate) mode: BuildMode,
    #[command(flatten)]
    pub(crate) capture: CaptureOutputArgs,
    #[command(flatten)]
    pub(crate) budget: PacketBudgetArgs,
}
