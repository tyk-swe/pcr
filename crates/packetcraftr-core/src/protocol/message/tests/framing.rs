// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
use super::*;

#[test]
fn sip_udp_without_content_length_uses_the_datagram() {
    let registry = builtin::registry();
    let mut packet = Packet::new();
    packet.push(Ethernet::default());
    packet.push(Ipv4::default());
    packet.push(Udp {
        destination_port: 5060,
        ..Default::default()
    });
    packet.push(Sip {
        headers: Records::default(),
        body: Bytes::from_static(b"datagram body"),
        ..Default::default()
    });
    let builder = crate::build::Builder::new(registry.clone());
    let built = builder
        .build(packet, Addresses::default(), Default::default())
        .unwrap();
    let decoded = crate::decode::Dissector::new(registry)
        .decode(
            Frame::without_timestamp(LinkType::ETHERNET, built.bytes.clone()).unwrap(),
            Default::default(),
        )
        .unwrap();
    let sip = decoded.packet.get::<Sip>().expect("valid SIP datagram");
    assert_eq!(sip.body.as_ref(), b"datagram body");
    assert!(decoded.diagnostics.is_empty(), "{:?}", decoded.diagnostics);
    let rebuilt = builder
        .build(decoded.packet, Addresses::default(), Default::default())
        .unwrap();
    assert_eq!(rebuilt.bytes, built.bytes);
}

#[test]
fn sip_tcp_still_requires_content_length() {
    let mut framer = crate::protocol::framing::Framer::new("sip");
    assert!(
        framer
            .progress(b"OPTIONS sip:service SIP/2.0\r\n\r\n", 65536)
            .is_err()
    );
}

#[test]
fn strict_build_checks_sip_and_rtsp_transport_framing() {
    let registry = builtin::registry();
    let messages: [(u16, Box<dyn Layer>); 2] = [
        (
            5060,
            Box::new(Sip {
                headers: Records::default(),
                ..Default::default()
            }),
        ),
        (
            554,
            Box::new(crate::protocol::application::rtsp::Rtsp {
                headers: Records::default(),
                body: Bytes::from_static(b"body"),
                ..Default::default()
            }),
        ),
    ];
    for (port, message) in messages {
        let mut packet = Packet::new();
        packet.push(Ipv4::default());
        packet.push(Tcp {
            destination_port: port,
            ..Default::default()
        });
        packet.push_boxed(message);
        let builder = crate::build::Builder::new(registry.clone());
        assert!(
            builder
                .build(packet.clone(), Addresses::default(), Default::default())
                .is_err()
        );
        let permissive = builder
            .build(
                packet,
                Addresses::default(),
                crate::build::Options {
                    mode: Mode::Permissive,
                    ..Default::default()
                },
            )
            .unwrap();
        assert!(
            permissive
                .diagnostics
                .iter()
                .any(|d| d.code == "build.message")
        );
    }
}

#[test]
fn unsupported_stream_tail_survives_strict_rebuild() {
    let registry = builtin::registry();
    let builder = crate::build::Builder::new(registry.clone());
    let mut packet = Packet::new();
    packet.push(Ethernet::default());
    packet.push(Ipv4::default());
    packet.push(Tcp {
        destination_port: 1883,
        ..Default::default()
    });
    packet.push(crate::layer::Raw::new(Bytes::from_static(b"\xc0\0\xf0\0")));
    let built = builder
        .build(packet, Addresses::default(), Default::default())
        .unwrap();
    let decoded = crate::decode::Dissector::new(registry)
        .decode(
            Frame::without_timestamp(LinkType::ETHERNET, built.bytes.clone()).unwrap(),
            Default::default(),
        )
        .unwrap();
    assert_eq!(
        decoded
            .packet
            .get::<crate::protocol::application::mqtt::Mqtt>()
            .unwrap()
            .packet_type,
        12
    );
    assert_eq!(
        decoded
            .packet
            .get::<crate::layer::Raw>()
            .unwrap()
            .bytes
            .as_ref(),
        b"\xf0\0"
    );
    let rebuilt = builder
        .build(decoded.packet, Addresses::default(), Default::default())
        .unwrap();
    assert_eq!(rebuilt.bytes, built.bytes);
}

#[test]
fn datagram_messages_reject_unframed_opaque_tails() {
    let mut packet = Packet::new();
    packet.push(Ethernet::default());
    packet.push(Ipv4::default());
    packet.push(Udp {
        destination_port: 5683,
        ..Default::default()
    });
    packet.push(crate::protocol::application::coap::Coap::default());
    packet.push(crate::layer::Raw::new(Bytes::from_static(b"\xff")));
    let builder = crate::build::Builder::new(builtin::registry());
    assert!(
        builder
            .build(packet.clone(), Addresses::default(), Default::default())
            .is_err()
    );
    let built = builder
        .build(
            packet,
            Addresses::default(),
            crate::build::Options {
                mode: Mode::Permissive,
                ..Default::default()
            },
        )
        .unwrap();
    assert!(built.diagnostics.iter().any(|d| d.code == "build.message"));
}

#[test]
fn folded_sip_and_rtsp_headers_preserve_bytes_and_frame_lengths() {
    // https://datatracker.ietf.org/doc/html/rfc3261#section-7.3.1 checked 2026-10-25.
    // https://datatracker.ietf.org/doc/html/rfc2326#section-4.2 checked 2026-10-25.
    for (name, start) in [
        ("sip", "OPTIONS sip:service SIP/2.0"),
        ("rtsp", "OPTIONS * RTSP/1.0"),
    ] {
        let wire = format!("{start}\r\nSubject: a\r\n b\r\nContent-Length:\r\n\t4\r\n\r\nbody");
        preserve_wire(
            name,
            wire.as_bytes(),
            &[
                (
                    "start_line",
                    Bytes::copy_from_slice(start.as_bytes()).into(),
                ),
                ("body", Bytes::from_static(b"body").into()),
                ("headers[0].value", Bytes::from_static(b" a\r\n b").into()),
            ],
        );
        for split in 1..wire.len() {
            let mut framer = crate::protocol::framing::Framer::new(name);
            assert_eq!(
                framer.progress(&wire.as_bytes()[..split], 65536).unwrap(),
                None
            );
            assert_eq!(
                framer.progress(wire.as_bytes(), 65536).unwrap(),
                Some(wire.len())
            );
        }
        let registry = builtin::registry();
        let decoded = registry
            .codec(name)
            .unwrap()
            .decode(
                Bytes::copy_from_slice(wire.as_bytes()),
                &DecodeContext {
                    parent: None,
                    registry: &registry,
                    network: None,
                    hop_limit: None,
                    discriminator: None,
                },
            )
            .unwrap();
        assert_eq!(
            decoded
                .layer
                .field_path(&"headers[0].value".parse().unwrap()),
            Some(Bytes::from_static(b" a\r\n b").into())
        );
    }
    let mut sip = Sip::default();
    sip.headers.0.push(record([
        ("name", Bytes::from_static(b"Subject").into()),
        ("value", Bytes::from_static(b" a\r\nInjected: value").into()),
    ]));
    let mut packet = Packet::new();
    packet.push(sip);
    assert!(
        crate::build::Builder::new(builtin::registry())
            .build(packet, Addresses::default(), Default::default())
            .is_err()
    );
}

#[test]
fn sip_udp_preserves_excess_bytes_after_declared_body() {
    let registry = builtin::registry();
    let builder = crate::build::Builder::new(registry.clone());
    let mut packet = Packet::new();
    packet.push(Ethernet::default());
    packet.push(Ipv4::default());
    packet.push(Udp {
        destination_port: 5060,
        ..Default::default()
    });
    packet.push(Sip::default());
    packet.push(crate::layer::Raw::new(Bytes::from_static(b"\r\nextra")));
    let built = builder
        .build(packet, Addresses::default(), Default::default())
        .unwrap();
    let decoded = crate::decode::Dissector::new(registry)
        .decode(
            Frame::without_timestamp(LinkType::ETHERNET, built.bytes.clone()).unwrap(),
            Default::default(),
        )
        .unwrap();
    assert!(decoded.diagnostics.is_empty(), "{:?}", decoded.diagnostics);
    assert!(decoded.packet.get::<Sip>().unwrap().body.is_empty());
    assert_eq!(
        decoded
            .packet
            .get::<crate::layer::Raw>()
            .unwrap()
            .bytes
            .as_ref(),
        b"\r\nextra"
    );
    assert_eq!(
        builder
            .build(decoded.packet, Addresses::default(), Default::default())
            .unwrap()
            .bytes,
        built.bytes
    );
}

#[test]
fn outer_ethernet_padding_does_not_extend_datagram_framing() {
    let registry = builtin::registry();
    let builder = crate::build::Builder::new(registry.clone());
    let mut packet = Packet::new();
    packet.push(Ethernet::default());
    packet.push(Ipv4::default());
    packet.push(Udp {
        destination_port: 5683,
        ..Default::default()
    });
    packet.push(crate::protocol::application::coap::Coap::default());
    let mut padded = builder
        .build(packet, Addresses::default(), Default::default())
        .unwrap()
        .bytes
        .to_vec();
    padded.resize(60, 0);
    let decoded = crate::decode::Dissector::new(registry)
        .decode(
            Frame::without_timestamp(LinkType::ETHERNET, Bytes::copy_from_slice(&padded)).unwrap(),
            Default::default(),
        )
        .unwrap();
    assert_eq!(
        decoded
            .packet
            .get::<crate::layer::Padding>()
            .unwrap()
            .outside_layer,
        Some(1)
    );
    assert_eq!(
        builder
            .build(decoded.packet, Addresses::default(), Default::default())
            .unwrap()
            .bytes
            .as_ref(),
        padded
    );
}

#[test]
fn rtsp_and_sip_methods_accept_the_token_grammar() {
    for (name, version) in [("rtsp", "RTSP/1.0"), ("sip", "SIP/2.0")] {
        for method in ["GET_PARAMETER", "SET_PARAMETER", "custom_method2"] {
            let wire = format!("{method} * {version}\r\nContent-Length: 0\r\n\r\n");
            preserve_wire(
                name,
                wire.as_bytes(),
                &[
                    (
                        "start_line",
                        Bytes::from(format!("{method} * {version}")).into(),
                    ),
                    ("body", Bytes::new().into()),
                ],
            );
        }
    }
}

#[test]
fn text_targets_and_content_lengths() {
    // https://datatracker.ietf.org/doc/html/rfc3261#section-25.1 checked 2026-10-25.
    // https://datatracker.ietf.org/doc/html/rfc2326#section-15.1 checked 2026-10-25.
    for (name, version) in [("sip", "SIP/2.0"), ("rtsp", "RTSP/1.0")] {
        assert!(decode(name, format!("OPTIONS  {version}\r\n\r\n").as_bytes()).is_err());
        for length in ["0", " 0\t", "\t\r\n 0 "] {
            let wire = format!("OPTIONS * {version}\r\nContent-Length:{length}\r\n\r\n");
            preserve_wire(
                name,
                wire.as_bytes(),
                &[
                    (
                        "start_line",
                        Bytes::from(format!("OPTIONS * {version}")).into(),
                    ),
                    (
                        "headers[0].name",
                        Bytes::from_static(b"Content-Length").into(),
                    ),
                    (
                        "headers[0].value",
                        Bytes::copy_from_slice(length.as_bytes()).into(),
                    ),
                    ("body", Bytes::new().into()),
                ],
            );
        }
        for length in ["+0", "-0", "", "\u{b}0", "0\u{c}", "\u{a0}0", "0\r\n 0"] {
            assert!(
                decode(
                    name,
                    format!("OPTIONS * {version}\r\nContent-Length:{length}\r\n\r\n").as_bytes()
                )
                .is_err(),
                "{length:?}"
            );
        }
    }
}

#[test]
fn resp_framing_matches_canonical_decoder_and_depth() {
    use crate::protocol::application::resp::{Resp, RespValue};
    // https://redis.io/docs/latest/develop/reference/protocol-spec/#integers checked 2026-10-25.
    for number in ["+1", "01", "-0", " 1"] {
        for tag in [":", "$", "*"] {
            let wire = format!("{tag}{number}\r\n");
            assert!(
                Framer::new("resp").progress(wire.as_bytes(), 4096).is_err(),
                "{wire:?}"
            );
            assert!(decode("resp", wire.as_bytes()).is_err());
            if number != " 1" {
                let registry = builtin::registry();
                let decoded = registry
                    .codec("resp")
                    .unwrap()
                    .decode(
                        Bytes::copy_from_slice(wire.as_bytes()),
                        &DecodeContext {
                            parent: None,
                            registry: &registry,
                            network: None,
                            hop_limit: None,
                            discriminator: None,
                        },
                    )
                    .unwrap();
                assert_eq!(decoded.layer.protocol_id().as_str(), "raw");
                assert_eq!(decoded.consumed, wire.len());
                assert_eq!(decoded.layer.field("bytes"), Some(Bytes::from(wire).into()));
            }
        }
    }
    for (leaf, value) in [
        ("+OK\r\n", RespValue::Simple(Bytes::from_static(b"OK"))),
        (":0\r\n", RespValue::Integer(0)),
        ("*0\r\n", RespValue::Array(Some(vec![]))),
        ("*-1\r\n", RespValue::Array(None)),
        ("$-1\r\n", RespValue::Bulk(None)),
        ("$0\r\n\r\n", RespValue::Bulk(Some(Bytes::new()))),
    ] {
        for depth in [15, 16] {
            let wire = format!("{}{leaf}", "*1\r\n".repeat(depth));
            let framed = Framer::new("resp").progress(wire.as_bytes(), 4096);
            let decoded = decode("resp", wire.as_bytes());
            if depth == 16 {
                assert!(framed.is_err(), "{leaf:?} at {depth}");
                assert!(decoded.is_err(), "{leaf:?} at {depth}");
                continue;
            }
            assert_eq!(framed.unwrap(), Some(wire.len()));
            let decoded = decoded.unwrap();
            let expected = (0..depth).fold(value.clone(), |inner, _| {
                RespValue::Array(Some(vec![inner]))
            });
            assert_eq!(
                decoded.layer.downcast_ref::<Resp>().unwrap().value,
                expected
            );
        }
    }
    let wire = b"$9223372036854775807\r\n";
    assert!(Framer::new("resp").progress(wire, 4096).is_err());
    for wire in [b"$0\r\n\r\n".as_slice(), b"$3\r\nabc\r\n"] {
        assert_eq!(
            Framer::new("resp").progress(wire, 4096).unwrap(),
            Some(wire.len())
        );
    }
}
