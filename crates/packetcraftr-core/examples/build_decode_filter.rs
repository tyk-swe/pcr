// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Builds a packet from a recipe expression, dissects the exact wire bytes,
//! and evaluates a display filter — fully offline against the built-in
//! protocol registry. No native features or network access required.
//!
//!     cargo run -p packetcraftr-core --example build_decode_filter

use std::sync::Arc;

use packetcraftr_core::build::{Builder, Options as BuildOptions};
use packetcraftr_core::codec::Context as BuildContext;
use packetcraftr_core::decode::{Dissector, Options as DecodeOptions};
use packetcraftr_core::expression;
use packetcraftr_core::filter::{Context as FilterContext, Filter, Options as FilterOptions};
use packetcraftr_core::frame::{Frame, LinkType};
use packetcraftr_core::protocol::builtin;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let registry = builtin::registry();

    // Build exact wire bytes for a UDP datagram between documentation
    // (TEST-NET-1) addresses; nothing leaves the process.
    let packet = expression::parse(
        "ipv4(src=192.0.2.1,dst=192.0.2.2)/udp(sport=12345,dport=9)/raw(text=hello)",
        &registry,
        expression::Options::default(),
    )?;
    let built = Builder::new(Arc::clone(&registry)).build(
        packet,
        BuildContext::default(),
        BuildOptions::default(),
    )?;
    println!("built {} bytes: {:x}", built.bytes.len(), built.bytes);

    // Dissect the same bytes as a bare IPv4 (linktype 228) frame.
    let frame = Frame::without_timestamp(LinkType::IPV4, built.bytes.clone())?;
    let decoded = Dissector::new(Arc::clone(&registry)).decode(frame, DecodeOptions::default())?;
    let layers: Vec<&str> = decoded
        .packet
        .iter()
        .map(|layer| layer.protocol_id().as_str())
        .collect();
    println!("decoded stack: {}", layers.join("/"));
    for layer in decoded.packet.iter() {
        if let Some(dport) = layer.field("dport") {
            println!("{}.dport = {dport:?}", layer.protocol_id().as_str());
        }
    }

    // A compiled filter resolves every named field against the registry up
    // front, so the `matches` call only evaluates the packet.
    let filter = Filter::compile("udp.dport == 9", &registry, FilterOptions::default())?;
    let matched = filter.matches(&FilterContext {
        decoded: &decoded,
        derived: &[],
        number: 1,
        tcp_stream: None,
        udp_stream: Some(0),
    })?;
    println!("filter `udp.dport == 9` matched: {matched}");
    Ok(())
}
