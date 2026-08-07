// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::BTreeMap;
use std::sync::Arc;

use packetcraftr_packet::{Packet, build, decode};
use packetcraftr_protocol::{builtin, support::BUILTIN_PROTOCOLS};

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
    let decoder = decode::Decoder::new(Arc::clone(&registry));
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
        let decoded = decoder
            .decode_with_root(
                first.bytes.clone(),
                support.protocol.into(),
                decode::Options::default(),
            )
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
