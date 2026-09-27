// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::capture_output::CaptureOutputArgs;
use crate::command_options::{BuildMode, PacketBudgetArgs, RecipeArgs, TemplateArgs};

pub(crate) const AFTER_LONG_HELP: &str = r"Examples:
  packetcraftr build --packet 'raw(text=hello)'
  packetcraftr --output raw build --packet-file packet.json
  packetcraftr --output ndjson build --packet 'ipv4(dst=192.0.2.1)/udp()' --axis '0.ttl=[1,64]' --axis '1.dport=[53,5353]'
  packetcraftr --output pcapng build --packet 'ipv4()/icmpv4(identifier=1)' --link-type ipv4 > packet.pcapng
  packetcraftr --output pcap build --packet 'ethernet()/ipv4()/udp()' --link-type ethernet --timestamp 1700000000.5 > packet.pcap

Packet sets use Cartesian order with the last axis varying fastest. Text and hex
emit one packet at a time. NDJSON emits packet events and one complete event;
errors may follow already emitted packets. JSON and raw require exactly one packet.

PCAP and PCAPNG write the packet set to stdout as a capture stream and require
--link-type naming the recipe's first layer. Every frame receives --timestamp
or the Unix epoch, keeping generated captures byte-deterministic.";

#[derive(Debug, clap::Args)]
pub(crate) struct Args {
    #[command(flatten)]
    pub(crate) recipe: RecipeArgs,
    #[command(flatten)]
    pub(crate) template: TemplateArgs,
    /// Enforce protocol invariants or preserve explicitly permissive values.
    #[arg(long, value_enum, default_value_t = BuildMode::Strict)]
    pub(crate) mode: BuildMode,
    #[command(flatten)]
    pub(crate) capture: CaptureOutputArgs,
    #[command(flatten)]
    pub(crate) budget: PacketBudgetArgs,
}
