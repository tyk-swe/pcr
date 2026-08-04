// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::Ipv4Addr;
use std::sync::Arc;

use bytes::Bytes;
use packetcraftr_packet::{Packet, layer::Raw, registry::ProtocolRegistry};
use packetcraftr_protocol::{builtin::registry as default_registry, network::Ipv4, transport::Udp};

fn fuzz_protocol_registry() -> Arc<ProtocolRegistry> {
    Arc::new(default_registry().unwrap())
}

fn udp_fuzz_packet() -> Packet {
    let mut packet = Packet::new();
    packet
        .push(Ipv4 {
            source: Ipv4Addr::new(192, 0, 2, 1),
            destination: Ipv4Addr::new(192, 0, 2, 2),
            ..Ipv4::default()
        })
        .push(Udp {
            source_port: 40_000,
            destination_port: 9,
            ..Udp::default()
        })
        .push(Raw::new(Bytes::from_static(b"abcdef")));
    packet
}

mod generation;
mod live;
mod validation;
