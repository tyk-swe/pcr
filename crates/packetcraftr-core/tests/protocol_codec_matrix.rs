// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
// Test code indexes fixtures and counts by hand; the fail-closed lints are
// for library paths.
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::SystemTime;

use packetcraftr_core::frame::{Frame, LinkType};
use packetcraftr_core::protocol::{builtin, support::BUILTIN_PROTOCOLS};
use packetcraftr_core::registry::Registry;
use packetcraftr_core::{Packet, build, decode};

/// A spare link type bound to an explicit root protocol so a dissection can
/// start below the capture layer.
const ROOT_LINK_TYPE: LinkType = LinkType(u32::MAX);

fn rooted_registry(root: &str) -> Arc<Registry> {
    Arc::new(
        builtin::registry_with(|builder| {
            builder.bind_link_type(ROOT_LINK_TYPE.0, root)?;
            Ok(())
        })
        .unwrap_or_else(|error| panic!("{root} root binding: {error}")),
    )
}

const REQUIRES_PACKET_CONTEXT_OR_CHILD: &[&str] = &[
    "bsd_loop", "bsd_null", "erspan", "esp", "icmpv6", "ipv6_srh", "llc", "padding", "pppoe",
    "sctp", "tcp", "udp", "vxlan",
];

#[test]
fn constructible_defaults_either_build_standalone_or_require_declared_context() {
    let registry = Arc::new(builtin::registry().expect("built-in registry should be valid"));
    let builder = build::Builder::new(Arc::clone(&registry));
    let mut rejected = Vec::new();
    let mut built_count = 0_usize;

    for support in BUILTIN_PROTOCOLS.iter().filter(|support| support.build) {
        let codec = registry
            .codec(support.protocol)
            .unwrap_or_else(|| panic!("{} should be registered", support.protocol));
        let layer = codec.make_layer(&BTreeMap::new()).unwrap_or_else(|error| {
            panic!("{} default construction failed: {error}", support.protocol)
        });
        let mut packet = Packet::new();
        packet.push_boxed(layer);

        let Ok(built) = builder.build(packet, build::Context::default(), build::Options::default())
        else {
            rejected.push(support.protocol);
            continue;
        };
        built_count += 1;
        assert_eq!(built.packet.len(), 1, "{}", support.protocol);
        assert_eq!(
            built
                .packet
                .layer(0)
                .map(|layer| layer.protocol_id().as_str()),
            Some(support.protocol),
            "{}",
            support.protocol
        );
        assert!(built.bytes.len() <= build::DEFAULT_MAX_PACKET_SIZE);
    }
    assert!(built_count > REQUIRES_PACKET_CONTEXT_OR_CHILD.len());
    assert_eq!(rejected, REQUIRES_PACKET_CONTEXT_OR_CHILD);
}

#[test]
fn exact_round_trip_builtins_decode_their_own_default_wire_image() {
    let registry = Arc::new(builtin::registry().expect("built-in registry should be valid"));
    let builder = build::Builder::new(Arc::clone(&registry));
    let mut rejected = Vec::new();
    let mut round_trip_count = 0_usize;

    for support in BUILTIN_PROTOCOLS
        .iter()
        .filter(|support| support.build && support.dissect && support.exact_round_trip)
    {
        let codec = registry
            .codec(support.protocol)
            .expect("codec should exist");
        let mut packet = Packet::new();
        packet.push_boxed(codec.make_layer(&BTreeMap::new()).unwrap_or_else(|error| {
            panic!("{} default construction failed: {error}", support.protocol)
        }));
        let Ok(first) = builder.build(packet, build::Context::default(), build::Options::default())
        else {
            rejected.push(support.protocol);
            continue;
        };
        round_trip_count += 1;
        let frame = Frame::new(SystemTime::UNIX_EPOCH, ROOT_LINK_TYPE, first.bytes.clone())
            .unwrap_or_else(|error| panic!("{} default frame failed: {error}", support.protocol));
        let decoded = decode::Dissector::new(rooted_registry(support.protocol))
            .decode(frame, decode::Options::default())
            .unwrap_or_else(|error| panic!("{} default decode failed: {error}", support.protocol));
        let rebuilt = builder
            .build(
                decoded.packet,
                build::Context::default(),
                build::Options::default(),
            )
            .unwrap_or_else(|error| panic!("{} decoded rebuild failed: {error}", support.protocol));
        assert_eq!(rebuilt.bytes, first.bytes, "{}", support.protocol);
    }
    assert!(round_trip_count > REQUIRES_PACKET_CONTEXT_OR_CHILD.len());
    assert_eq!(rejected, REQUIRES_PACKET_CONTEXT_OR_CHILD);
}
