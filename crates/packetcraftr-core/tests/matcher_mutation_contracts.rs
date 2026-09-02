// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
// Test code indexes fixtures and counts by hand; the fail-closed lints are
// for library paths.
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

mod common;

use common::packets::ipv4;
use common::registry;
use std::sync::Arc;
use std::time::SystemTime;

use bytes::Bytes;
use packetcraftr_core::frame::{Frame, LinkType};
use packetcraftr_core::layer::{Padding, Raw};
use packetcraftr_core::protocol::transport::Tcp;
use packetcraftr_core::{Packet, build, decode};

#[test]
fn tcp_response_correlation_uses_decoded_payload_after_every_mutation_api() {
    let registry = registry();
    let tcp_matcher = registry.matcher("tcp").expect("TCP matcher");
    let mut response = Packet::new();
    response.push(ipv4([198, 51, 100, 2], [192, 0, 2, 1]));
    response.push(Tcp {
        source_port: 80,
        destination_port: 40_000,
        acknowledgment: 104,
        flags: Tcp::ACK,
        ..Tcp::default()
    });

    type Mutator = fn(&mut Packet);
    let mutators: [(&str, Mutator); 3] = [
        ("get_mut", |packet| {
            packet.get_mut::<Raw>().expect("Raw").bytes = Bytes::from_static(&[2, 3, 4]);
        }),
        ("layer_mut", |packet| {
            packet
                .layer_mut(2)
                .expect("Raw layer")
                .as_any_mut()
                .downcast_mut::<Raw>()
                .expect("Raw type")
                .bytes = Bytes::from_static(&[2, 3, 4]);
        }),
        ("replace", |packet| {
            packet
                .replace(2, Raw::new(Bytes::from_static(&[2, 3, 4])))
                .expect("Raw replacement");
        }),
    ];

    for (name, mutate) in mutators {
        let mut request = Packet::new();
        request.push(ipv4([192, 0, 2, 1], [198, 51, 100, 2]));
        request.push(Tcp {
            source_port: 40_000,
            destination_port: 80,
            sequence: 100,
            ..Tcp::default()
        });
        request.push(Raw::new(Bytes::from_static(&[1])));
        let builder = build::Builder::new(Arc::clone(&registry));
        let built = builder
            .build(
                request,
                build::Context::default(),
                build::Options::default(),
            )
            .expect("TCP request builds");
        let frame = Frame::new(SystemTime::UNIX_EPOCH, LinkType::IPV4, built.bytes)
            .expect("TCP request frame");
        let mut request = decode::Dissector::new(Arc::clone(&registry))
            .decode(frame, decode::Options::default())
            .expect("TCP request decodes")
            .packet;

        assert_eq!(request.encoded_payload_length(1), Some(1), "{name} setup");
        mutate(&mut request);
        assert_eq!(
            request.encoded_payload_length(1),
            None,
            "{name} invalidates"
        );
        assert!(
            tcp_matcher.matches(&request, &response).is_some(),
            "{name} must use the new TCP payload length"
        );
    }
}

#[test]
fn tcp_response_correlation_preserves_syn_fin_and_trailing_padding_rules() {
    let registry = registry();
    let matcher = registry.matcher("tcp").expect("TCP matcher");
    let mut request = Packet::new();
    request.push(ipv4([192, 0, 2, 1], [198, 51, 100, 2]));
    request.push(Tcp {
        source_port: 40_000,
        destination_port: 80,
        sequence: 100,
        flags: Tcp::SYN | Tcp::FIN,
        ..Tcp::default()
    });
    request.push(Raw::new(Bytes::from_static(&[1])));
    request.push(Padding::after_layer(Bytes::from_static(&[0xaa, 0xbb]), 0));

    let built = build::Builder::new(Arc::clone(&registry))
        .build(
            request,
            build::Context::default(),
            build::Options::default(),
        )
        .expect("padded TCP request builds");
    assert_eq!(built.packet.encoded_payload_length(1), Some(3));

    let mut response = Packet::new();
    response.push(ipv4([198, 51, 100, 2], [192, 0, 2, 1]));
    response.push(Tcp {
        source_port: 80,
        destination_port: 40_000,
        acknowledgment: 103,
        flags: Tcp::ACK,
        ..Tcp::default()
    });
    assert!(matcher.matches(&built.packet, &response).is_some());
}
