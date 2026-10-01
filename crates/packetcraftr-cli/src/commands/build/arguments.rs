// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::capture_output::CaptureOutputArgs;
use super::session::SessionArgs;
use crate::command_options::{BuildMode, PacketBudgetArgs, RecipeArgs, TemplateArgs};

pub(crate) const AFTER_LONG_HELP: &str = r"Examples:
  packetcraftr build --packet 'raw(text=hello)'
  packetcraftr --output raw build --packet-file packet.json
  packetcraftr --output ndjson build --packet 'ipv4(dst=192.0.2.1)/udp()' --axis '0.ttl=[1,64]' --axis '1.dport=[53,5353]'
  packetcraftr build --packet-file vlan.json --set ipv4.ttl=5 --set udp.destination_port=53
  packetcraftr build --packet-file tunnel.json --set ipv4#2.ttl=9
  packetcraftr --output pcapng build --packet 'ipv4()/icmpv4(identifier=1)' --link-type ipv4 > packet.pcapng
  packetcraftr --output pcap build --packet 'ethernet()/ipv4()/udp()' --link-type ethernet --timestamp 1700000000.5 > packet.pcap
  packetcraftr --output pcap build --session tcp --packet 'ethernet()/ipv4(src=192.0.2.1,dst=192.0.2.2)/tcp(dport=80)/raw(text=ping)' --link-type ethernet --session-response-file reply.bin > conversation.pcap

Packet sets use Cartesian order with the last axis varying fastest. Text and hex
emit one packet at a time. NDJSON emits packet events and one complete event;
errors may follow already emitted packets. JSON and raw require exactly one packet.

PCAP and PCAPNG write the packet set to stdout as a capture stream and require
--link-type naming the recipe's first layer. Every frame receives --timestamp
or the Unix epoch, keeping generated captures byte-deterministic.

--session expands the recipe into a deterministic TCP or UDP conversation: the
recipe is the client-to-server packet and its payload layer is the request.
Equal inputs produce byte-identical frames, spaced --session-step-ns apart from
--timestamp in capture output.

See `packetcraftr topics expressions` for the packet expression syntax.
See `packetcraftr topics filters` for the display-filter language.";

#[derive(Debug, clap::Args)]
pub(crate) struct Args {
    #[command(flatten)]
    pub(crate) recipe: RecipeArgs,
    /// Override one recipe field before axes expand, e.g. ipv4.ttl=5 or
    /// ipv4#2.ttl=9. The selector is <protocol>[#occurrence].<field> or a
    /// zero-based LAYER.FIELD, and the value follows packet-expression syntax.
    /// Repeat up to 64 times; a later override of the same field wins.
    #[arg(long = "set", value_name = "SELECTOR=VALUE")]
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
