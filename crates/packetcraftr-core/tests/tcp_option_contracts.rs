// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
mod common;

use bytes::Bytes;
use common::packets::ipv4;
use packetcraftr_core::{
    build::Builder,
    decode::Dissector,
    document, expression,
    field::FieldValue,
    filter,
    frame::{Frame, LinkType},
    layer::Layer,
    packet::Packet,
    protocol::builtin,
    protocol::transport::{SackBlock, Tcp, TcpOption},
    template::Template,
};
use std::time::UNIX_EPOCH;

fn build(recipe: &str) -> packetcraftr_core::build::BuiltPacket {
    let registry = builtin::registry();
    let packet = expression::parse(recipe, &registry, Default::default()).unwrap();
    Builder::new(registry)
        .build(packet, Default::default(), Default::default())
        .unwrap()
}

fn dissect(bytes: Bytes) -> packetcraftr_core::decode::DecodedPacket {
    Dissector::new(builtin::registry())
        .decode(
            Frame::new(UNIX_EPOCH, LinkType::IPV4, bytes).unwrap(),
            Default::default(),
        )
        .unwrap()
}

fn reencode(packet: Packet) -> Bytes {
    Builder::new(builtin::registry())
        .build(packet, Default::default(), Default::default())
        .unwrap()
        .bytes
}

#[test]
fn typed_tcp_options_construct_in_order_and_decode_back() {
    let built = build(concat!(
        "ipv4(source=192.0.2.1,destination=198.51.100.2)/",
        "tcp(source_port=40000,destination_port=443,flags=2,options=[",
        "{kind=2,mss=1460},{kind=4},{kind=8,tsval=16909060,tsecr=2694881440},",
        "{kind=1},{kind=3,window_scale=7},{kind=5,",
        "sack=[{left_edge=100,right_edge=200},{left_edge=300,right_edge=400}]}])",
    ));
    let decoded = dissect(built.bytes.clone());
    let options = &decoded.packet.get::<Tcp>().unwrap().options;
    assert_eq!(
        options[..6],
        [
            TcpOption::Mss(1460),
            TcpOption::SackPermitted,
            TcpOption::Timestamps {
                value: 16_909_060,
                echo_reply: 2_694_881_440
            },
            TcpOption::Nop,
            TcpOption::WindowScale(7),
            TcpOption::Sack(vec![
                SackBlock {
                    left_edge: 100,
                    right_edge: 200
                },
                SackBlock {
                    left_edge: 300,
                    right_edge: 400
                }
            ])
        ]
    );
    // Option bytes: 4+2+10+1+3+18 = 38, padded to 40 with two EOL zeros.
    assert_eq!(
        options[6..],
        [
            TcpOption::End,
            TcpOption::Trailing(Bytes::from_static(&[0]))
        ],
        "alignment padding after EOL stays opaque"
    );
    assert_eq!(reencode(decoded.packet.clone()), built.bytes);
}

#[test]
fn unknown_and_malformed_tcp_options_keep_exact_wire_bytes() {
    // kind 30 (unknown), a kind 2 with a nonstandard length, then a truncated
    // tail that cannot be a TLV: all must survive decode/encode unchanged.
    let mut packet = Packet::new();
    packet.push(ipv4([192, 0, 2, 1], [198, 51, 100, 2]));
    packet.push(Tcp {
        source_port: 40_000,
        destination_port: 443,
        options: vec![
            TcpOption::Raw {
                kind: 30,
                data: Bytes::from_static(&[9, 9]),
            },
            TcpOption::Raw {
                kind: 2,
                data: Bytes::from_static(&[1, 2, 3]),
            },
            TcpOption::Trailing(Bytes::from_static(&[4, 0xee])),
        ],
        ..Tcp::default()
    });
    packet.push(packetcraftr_core::layer::Raw::new(b"payload".to_vec()));
    let built = Builder::new(builtin::registry())
        .build(packet, Default::default(), Default::default())
        .unwrap();
    // 4 + 5 + 2 = 11 option bytes padded to 12; wire keeps them verbatim.
    let options_area = &built.bytes[40..52];
    assert_eq!(
        options_area,
        &[30, 4, 9, 9, 2, 5, 1, 2, 3, 4, 0xee, 0],
        "unknown, nonstandard-length, and malformed bytes stay in order"
    );
    let decoded = dissect(built.bytes.clone());
    let tcp = decoded.packet.get::<Tcp>().unwrap();
    // The malformed `04 ee` option start swallows everything left, including
    // the padding byte, into one verbatim trailing span.
    assert!(matches!(
        tcp.options.as_slice(),
        [
            TcpOption::Raw { kind: 30, .. },
            TcpOption::Raw { kind: 2, .. },
            TcpOption::Trailing(_)
        ]
    ));
    let [.., TcpOption::Trailing(tail)] = tcp.options.as_slice() else {
        panic!("options must end in trailing bytes");
    };
    assert_eq!(tail.as_ref(), &[4, 0xee, 0]);
    assert_eq!(reencode(decoded.packet.clone()), built.bytes);
}

#[test]
fn tcp_option_fields_filter_project_and_expand() {
    let registry = builtin::registry();
    let built = build(concat!(
        "ipv4(source=192.0.2.1,destination=198.51.100.2)/",
        "tcp(destination_port=443,flags=2,options=[{kind=2,mss=1460},{kind=3,window_scale=7}])"
    ));
    let decoded = dissect(built.bytes);
    for (expression_text, expected) in [
        ("tcp.options[0].mss == 1460", true),
        ("tcp.options[0].kind == 2", true),
        ("tcp.options[1].window_scale == 7", true),
        ("tcp.options[2].kind == 0", true),
        ("tcp.options[0].mss == 1200", false),
    ] {
        let filter =
            filter::Filter::compile(expression_text, &registry, Default::default()).unwrap();
        assert_eq!(
            filter
                .matches(&filter::Context {
                    decoded: &decoded,
                    derived: &[],
                    number: 1,
                    tcp_stream: None,
                    udp_stream: None
                })
                .unwrap(),
            expected,
            "{expression_text}"
        );
    }
    // Nested paths project typed option members.
    let tcp = decoded.packet.get::<Tcp>().unwrap();
    assert_eq!(
        tcp.field_path("options[0].mss"),
        Some(FieldValue::Unsigned(1460))
    );
    // Template axes reach into typed option members.
    let packet = expression::parse(
        concat!(
            "ipv4(source=192.0.2.1,destination=198.51.100.2)/",
            "tcp(options=[{kind=2,mss=536}])"
        ),
        &registry,
        Default::default(),
    )
    .unwrap();
    let template =
        Template::new(packet).axis(1, "options[0].mss", vec![536u16.into(), 1460u16.into()]);
    let values: Vec<u64> = template
        .expand(2)
        .unwrap()
        .map(|packet| {
            packet
                .unwrap()
                .get::<Tcp>()
                .unwrap()
                .field_path("options[0].mss")
                .unwrap()
                .as_u64()
                .unwrap()
        })
        .collect();
    assert_eq!(values, [536, 1460]);
}

#[test]
fn tcp_options_enforce_construction_limits_and_raw_byte_input() {
    let registry = builtin::registry();
    for recipe in [
        // Raw kinds 0 and 1 carry no length byte; data is malformed there.
        "tcp(options=[{kind=0,data=hex(\"aa\")}])",
        "tcp(options=[{kind=1,data=hex(\"aa\")}])",
        // Trailing bytes must be the last list member.
        "tcp(options=[{trailing=hex(\"aa\")},{kind=1}])",
        // Members must match the declared kind.
        "tcp(options=[{kind=2,window_scale=7}])",
        "tcp(options=[{kind=3,mss=1460}])",
        "tcp(options=[{kind=8,tsval=1}])",
        // Forty-one bytes of options exceed the TCP data-offset limit. The IP
        // envelope keeps the rejection attributable to the option area rather
        // than to the transport checksum a bare `tcp()` recipe cannot resolve.
        "ipv4(source=192.0.2.1,destination=198.51.100.2)/tcp(options=hex(\"020405b401010101010101010101010101010101010101010101010101010101010101010101010101\"))",
        // A SACK list longer than the 31 blocks the length byte can address.
        "tcp(options=[{kind=5,sack=[{left_edge=1,right_edge=2},{left_edge=1,right_edge=2},{left_edge=1,right_edge=2},{left_edge=1,right_edge=2},{left_edge=1,right_edge=2},{left_edge=1,right_edge=2},{left_edge=1,right_edge=2},{left_edge=1,right_edge=2},{left_edge=1,right_edge=2},{left_edge=1,right_edge=2},{left_edge=1,right_edge=2},{left_edge=1,right_edge=2},{left_edge=1,right_edge=2},{left_edge=1,right_edge=2},{left_edge=1,right_edge=2},{left_edge=1,right_edge=2},{left_edge=1,right_edge=2},{left_edge=1,right_edge=2},{left_edge=1,right_edge=2},{left_edge=1,right_edge=2},{left_edge=1,right_edge=2},{left_edge=1,right_edge=2},{left_edge=1,right_edge=2},{left_edge=1,right_edge=2},{left_edge=1,right_edge=2},{left_edge=1,right_edge=2},{left_edge=1,right_edge=2},{left_edge=1,right_edge=2},{left_edge=1,right_edge=2},{left_edge=1,right_edge=2},{left_edge=1,right_edge=2},{left_edge=1,right_edge=2}]}])",
    ] {
        let rejected = match expression::parse(recipe, &registry, Default::default()) {
            Err(_) => true,
            Ok(packet) => Builder::new(registry.clone())
                .build(packet, Default::default(), Default::default())
                .is_err(),
        };
        assert!(rejected, "{recipe} must be rejected");
    }
    // The limit is forty bytes, not thirty-nine: the largest legal option area
    // still builds, so the rejection above is attributable to the one extra
    // byte rather than to anything else in the recipe.
    let largest = expression::parse(
        "ipv4(source=192.0.2.1,destination=198.51.100.2)/tcp(options=hex(\"020405b4010101010101010101010101010101010101010101010101010101010101010101010101\"))",
        &registry,
        Default::default(),
    )
    .unwrap();
    Builder::new(registry.clone())
        .build(largest, Default::default(), Default::default())
        .expect("forty option bytes fit the TCP data offset");
    // Verbatim option bytes still parse into typed entries on construction.
    let packet = expression::parse(
        "tcp(options=hex(\"020405b401030307\"))",
        &registry,
        Default::default(),
    )
    .unwrap();
    let tcp = packet.get::<Tcp>().unwrap();
    assert_eq!(
        tcp.options,
        vec![
            TcpOption::Mss(1460),
            TcpOption::Nop,
            TcpOption::WindowScale(7)
        ]
    );
}

#[test]
fn decoded_tcp_options_round_trip_through_documents() {
    let built = build(concat!(
        "ipv4(source=192.0.2.1,destination=198.51.100.2)/",
        "tcp(destination_port=443,flags=2,options=[{kind=2,mss=1460},{kind=30,data=hex(\"0909\")}])"
    ));
    let decoded = dissect(built.bytes.clone());
    let document = document::Packet::from_packet(&decoded.packet);
    let recreated = document.to_packet(&builtin::registry(), 8).unwrap();
    assert_eq!(
        recreated.get::<Tcp>().unwrap().options,
        decoded.packet.get::<Tcp>().unwrap().options
    );
    assert_eq!(reencode(recreated), built.bytes);

    // A standard kind carrying a nonstandard wire length decodes to `Raw`, and
    // the field document has to carry it back as `Raw` instead of demanding the
    // typed member that kind normally declares.
    let malformed = build(concat!(
        "ipv4(source=192.0.2.1,destination=198.51.100.2)/",
        "tcp(destination_port=443,flags=2,options=hex(\"1e04090902050102030400\"))"
    ));
    let decoded = dissect(malformed.bytes.clone());
    assert_eq!(
        decoded.packet.get::<Tcp>().unwrap().options,
        vec![
            TcpOption::Raw {
                kind: 30,
                data: Bytes::from_static(&[0x09, 0x09])
            },
            TcpOption::Raw {
                kind: 2,
                data: Bytes::from_static(&[0x01, 0x02, 0x03])
            },
            TcpOption::Trailing(Bytes::from_static(&[0x04, 0x00, 0x00])),
        ]
    );
    let document = document::Packet::from_packet(&decoded.packet);
    let recreated = document.to_packet(&builtin::registry(), 8).unwrap();
    assert_eq!(
        recreated.get::<Tcp>().unwrap().options,
        decoded.packet.get::<Tcp>().unwrap().options
    );
    assert_eq!(reencode(recreated), malformed.bytes);
}
