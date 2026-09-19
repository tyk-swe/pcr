// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
use packetcraftr_core::{
    build::Builder,
    decode::Dissector,
    frame::{Frame, LinkType},
    layer::Raw,
    packet::Packet,
    protocol::{
        application::{dns::Dns, http::Http},
        builtin,
        network::Ipv4,
        transport::Tcp,
    },
};
use std::time::UNIX_EPOCH;
#[test]
fn per_frame_application_headers_round_trip_with_unconsumed_tcp_tail() {
    for dns in [false, true] {
        let mut packet = Packet::new();
        packet.push(Ipv4 {
            source: "192.0.2.1".parse().unwrap(),
            destination: "198.51.100.2".parse().unwrap(),
            ..Default::default()
        });
        packet.push(Tcp {
            source_port: 40000,
            destination_port: if dns { 53 } else { 80 },
            ..Default::default()
        });
        if dns {
            packet.push(Dns::default());
            packet.push(Raw::new(vec![0, 12, 0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]));
        } else {
            packet.push(
                Http::try_from(b"GET / HTTP/1.1\r\nHost: example.test\r\n\r\n".as_slice()).unwrap(),
            );
            packet.push(Raw::new(b"GET /next HTTP/1.1\r\n\r\n".to_vec()));
        }
        let builder = Builder::new(builtin::registry());
        let built = builder
            .build(packet, Default::default(), Default::default())
            .unwrap();
        let decoded = Dissector::new(builtin::registry())
            .decode(
                Frame::new(UNIX_EPOCH, LinkType::IPV4, built.bytes.clone()).unwrap(),
                Default::default(),
            )
            .unwrap();
        assert_eq!(decoded.packet.get::<Dns>().is_some(), dns);
        assert_eq!(decoded.packet.get::<Http>().is_some(), !dns);
        assert!(decoded.packet.get::<Raw>().is_some());
        let rebuilt = builder
            .build(decoded.packet, Default::default(), Default::default())
            .unwrap();
        assert_eq!(rebuilt.bytes, built.bytes);
    }
}
