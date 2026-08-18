// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::Ipv4Addr;
use std::sync::Arc;

use bytes::Bytes;
use packetcraftr_core::Packet;
use packetcraftr_core::build::{Builder, Context, Mode, Options};
use packetcraftr_core::layer::{Malformed, Padding, Raw};
use packetcraftr_core::protocol::network::Ipv4;
use packetcraftr_core::protocol::transport::Udp;

fn builder() -> Builder {
    Builder::new(Arc::new(
        packetcraftr_core::protocol::builtin::registry().expect("built-in registry"),
    ))
}

fn raw_packet() -> Packet {
    let mut packet = Packet::new();
    packet.push(Raw::new(Bytes::from_static(b"payload")));
    packet
}

#[test]
fn permissive_build_mode_requires_live_opt_in() {
    let built = builder()
        .build(
            raw_packet(),
            Context::default(),
            Options {
                mode: Mode::Permissive,
                ..Options::default()
            },
        )
        .expect("permissive raw packet builds");

    assert!(built.requires_live_opt_in);
}

#[test]
fn explicit_malformed_layer_requires_live_opt_in() {
    let mut packet = Packet::new();
    packet.push(Malformed::new(
        None,
        Bytes::from_static(&[0xff]),
        "intentional malformed fixture",
    ));
    let built = builder()
        .build(packet, Context::default(), Options::default())
        .expect("explicit malformed layer builds");

    assert!(built.requires_live_opt_in);
}

#[test]
fn network_trailer_requires_live_opt_in() {
    let mut packet = Packet::new();
    packet
        .push(Ipv4 {
            source: Ipv4Addr::new(192, 0, 2, 1),
            destination: Ipv4Addr::new(198, 51, 100, 1),
            ..Ipv4::default()
        })
        .push(Udp {
            destination_port: 9,
            ..Udp::default()
        })
        .push(Raw::new(Bytes::from_static(b"payload")))
        .push(Padding::after_layer(Bytes::from_static(&[0xaa]), 0));
    let built = builder()
        .build(packet, Context::default(), Options::default())
        .expect("packet with a network trailer builds");

    assert!(built.requires_live_opt_in);
}

#[test]
fn ordinary_strict_packet_does_not_require_live_opt_in() {
    let built = builder()
        .build(raw_packet(), Context::default(), Options::default())
        .expect("strict raw packet builds");

    assert!(!built.requires_live_opt_in);
}
