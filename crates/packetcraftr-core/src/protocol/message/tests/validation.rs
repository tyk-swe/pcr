// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
use super::*;

#[test]
fn ospfv2_preserves_the_separate_authentication_digest() {
    // https://datatracker.ietf.org/doc/html/rfc2328#appendix-D.3 checked 2026-10-25.
    let manifest: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../../../examples/captures/protocols.manifest.json"
    ))
    .unwrap();
    let reference = manifest["protocols"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["protocol"] == "ospfv2")
        .unwrap();
    let mut wire = crate::layer::parse_hex(reference["wire_hex"].as_str().unwrap())
        .unwrap()
        .to_vec();
    let declared = wire.len();
    wire[12..14].copy_from_slice(&[0, 0]);
    wire[14..16].copy_from_slice(&[0, 2]);
    wire[16..24].copy_from_slice(&[0, 0, 7, 16, 0, 0, 0, 1]);
    wire.extend_from_slice(&[0xa5; 16]);
    assert_eq!(
        usize::from(u16::from_be_bytes([wire[2], wire[3]])),
        declared
    );
    let registry = builtin::registry();
    let codec = registry.codec("ospfv2").unwrap();
    let decoded = codec
        .decode(
            Bytes::copy_from_slice(&wire),
            &DecodeContext {
                parent: Some(crate::layer::Id::new("ipv4")),
                registry: &registry,
                network: None,
                hop_limit: None,
                discriminator: None,
            },
        )
        .expect("authenticated OSPF is not a length error");
    assert_eq!(decoded.consumed, wire.len());
    assert_fields(
        decoded.layer.as_ref(),
        &[
            ("auth_type", 2_u16.into()),
            (
                "auth_data",
                Bytes::from_static(b"\0\0\x07\x10\0\0\0\x01").into(),
            ),
            ("auth_trailer", Bytes::from_static(&[0xa5; 16]).into()),
        ],
    );
    let mut packet = Packet::new();
    packet.push_boxed(decoded.layer);
    let addresses = Addresses::default();
    let encoded = registry
        .codec(packet.layer(0).unwrap().protocol_id().as_str())
        .unwrap()
        .encode(
            packet.layer(0).unwrap(),
            &[],
            &EncodeContext {
                packet: &packet,
                index: 0,
                build_context: &addresses,
                mode: Mode::Strict,
                registry: &registry,
                child: None,
                remaining_packet_bytes: 65536,
            },
        )
        .unwrap();
    assert_eq!(encoded.prefix, wire);
}

#[test]
fn large_cdp_checksum_round_trips_without_overflow() {
    // https://raw.githubusercontent.com/wireshark/wireshark/master/epan/dissectors/packet-cdp.c checked 2026-10-25.
    let mut packet = Packet::new();
    packet.push(crate::protocol::link::cdp::Cdp {
        version: 2,
        ttl: 180,
        tlvs: Records(
            (0..3)
                .map(|_| {
                    record([
                        ("kind", 1_u8.into()),
                        ("value", Bytes::from(vec![0xff; 65_530]).into()),
                    ])
                })
                .collect(),
        ),
        ..Default::default()
    });
    let registry = builtin::registry();
    let built = crate::build::Builder::new(registry.clone())
        .build(packet, Addresses::default(), Default::default())
        .unwrap();
    // Each TLV folds to 0xffff, leaving the complement of 0x02b4.
    let expected = [2, 180, 0xfd, 0x4b]
        .into_iter()
        .chain((0..3).flat_map(|_| {
            [0, 1, 0xff, 0xfe]
                .into_iter()
                .chain(std::iter::repeat_n(0xff, 65_530))
        }))
        .collect::<Vec<_>>();
    assert_eq!(built.bytes.as_ref(), expected);
    preserve_wire(
        "cdp",
        &expected,
        &[
            ("checksum", 0xfd4b_u16.into()),
            (
                "tlvs",
                field::Value::List(
                    (0..3)
                        .map(|_| {
                            field::Value::Object(record([
                                ("kind", 1_u8.into()),
                                ("value", Bytes::from(vec![0xff; 65_530]).into()),
                            ]))
                        })
                        .collect(),
                ),
            ),
        ],
    );
}

#[test]
fn radius_padding_is_separate_from_attributes() {
    let registry = builtin::registry();
    let mut wire = vec![1, 7, 0, 20];
    wire.extend_from_slice(&[0; 16]);
    wire.extend_from_slice(&[0xff; 4]);
    let decoded = registry
        .codec("radius")
        .unwrap()
        .decode(
            Bytes::copy_from_slice(&wire),
            &DecodeContext {
                parent: Some(crate::layer::Id::new("udp")),
                registry: &registry,
                network: None,
                hop_limit: None,
                discriminator: None,
            },
        )
        .unwrap();
    assert_eq!(decoded.layer.protocol_id().as_str(), "radius");
    assert_eq!(decoded.consumed, 20);
    assert_eq!(decoded.payload_len, 4);
    let mut packet = Packet::new();
    packet.push_boxed(decoded.layer);
    packet.push(crate::layer::Raw::new(Bytes::copy_from_slice(&wire[20..])));
    let built = crate::build::Builder::new(registry)
        .build(packet, Addresses::default(), Default::default())
        .unwrap();
    assert_eq!(built.bytes.as_ref(), wire);
}

#[test]
fn ethernet_ip_errors_preserve_opaque_command_data() {
    for command in [0x65_u16, 0x6f, 0x70] {
        for data in [&[][..], &[0xa5, 0x5a][..]] {
            let mut wire = Vec::from(command.to_le_bytes());
            wire.extend_from_slice(&(data.len() as u16).to_le_bytes());
            wire.extend_from_slice(&[0; 4]);
            wire.extend_from_slice(&100_u32.to_le_bytes());
            wire.extend_from_slice(&[0; 12]);
            wire.extend_from_slice(data);
            preserve_wire(
                "ethernet_ip",
                &wire,
                &[
                    ("command", command.into()),
                    ("status", 100_u32.into()),
                    ("data", Bytes::copy_from_slice(data).into()),
                ],
            );
        }
    }
}

#[test]
fn ipfix_options_template_withdrawals_round_trip() {
    // https://datatracker.ietf.org/doc/html/rfc7011#section-8.1 checked 2026-10-25.
    for templates in [vec![256_u16], vec![256, 257], vec![3]] {
        let mut wire = vec![0, 10];
        wire.extend_from_slice(&(20 + templates.len() as u16 * 4).to_be_bytes());
        wire.extend_from_slice(&[0; 12]);
        wire.extend_from_slice(&3_u16.to_be_bytes());
        wire.extend_from_slice(&(4 + templates.len() as u16 * 4).to_be_bytes());
        for id in &templates {
            wire.extend_from_slice(&id.to_be_bytes());
            wire.extend_from_slice(&[0, 0]);
        }
        preserve_wire(
            "ipfix",
            &wire,
            &[
                ("sets[0].id", 3_u16.into()),
                (
                    "sets[0].records",
                    field::Value::List(
                        templates
                            .into_iter()
                            .map(|id| {
                                field::Value::Object(record([
                                    ("template_id", id.into()),
                                    ("scope_count", 0_u16.into()),
                                    ("fields", field::Value::List(vec![])),
                                ]))
                            })
                            .collect(),
                    ),
                ),
            ],
        );
    }
}

#[test]
fn amqp_content_headers_require_complete_property_flags() {
    // https://www.rabbitmq.com/resources/specs/amqp0-9-1.pdf section 4.2.6 checked 2026-10-25.
    for (payload, valid) in [
        (vec![0; 12], false),
        (vec![0; 13], false),
        (vec![0; 14], true),
        (
            {
                let mut p = vec![0; 14];
                p[13] = 1;
                p
            },
            false,
        ),
        (
            {
                let mut p = vec![0; 16];
                p[13] = 1;
                p
            },
            true,
        ),
    ] {
        let mut packet = Packet::new();
        packet.push(crate::protocol::application::amqp::Amqp {
            frame_type: 2,
            channel: 1,
            payload: Bytes::copy_from_slice(&payload),
            ..Default::default()
        });
        let built = crate::build::Builder::new(builtin::registry()).build(
            packet,
            Addresses::default(),
            Default::default(),
        );
        let mut wire = vec![2, 0, 1];
        wire.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        wire.extend_from_slice(&payload);
        wire.push(0xce);
        let decoded = decode("amqp", &wire);
        if !valid {
            assert!(built.is_err());
            assert!(decoded.is_err());
            continue;
        }
        assert_eq!(built.unwrap().bytes.as_ref(), wire);
        assert_fields(
            decoded.unwrap().layer.as_ref(),
            &[
                ("frame_type", 2_u8.into()),
                ("channel", 1_u16.into()),
                ("payload", Bytes::from(payload).into()),
            ],
        );
    }
}

#[test]
fn bacnet_segment_ack_requires_its_window_size() {
    // https://raw.githubusercontent.com/wireshark/wireshark/master/epan/dissectors/packet-bacapp.c checked 2026-10-25.
    let ack = b"\x40\x01\x02\x01";
    for len in 0..=ack.len() {
        let registry = builtin::registry();
        let mut packet = Packet::new();
        packet.push(crate::protocol::application::bacnet_ip::BacnetIp {
            bvlc_function: 10,
            control: 0,
            data: Bytes::copy_from_slice(&ack[..len]),
            ..Default::default()
        });
        let built = crate::build::Builder::new(registry).build(
            packet,
            Addresses::default(),
            Default::default(),
        );
        let mut wire = vec![0x81, 10, 0, (6 + len) as u8, 1, 0];
        wire.extend_from_slice(&ack[..len]);
        let decoded = decode("bacnet_ip", &wire);
        if len < ack.len() {
            assert!(built.is_err());
            assert!(decoded.is_err());
            continue;
        }
        assert_eq!(built.unwrap().bytes.as_ref(), wire);
        assert_fields(
            decoded.unwrap().layer.as_ref(),
            &[
                ("bvlc_function", 10_u8.into()),
                ("data", Bytes::from_static(ack).into()),
            ],
        );
    }
}

#[test]
fn other_slow_protocols_remain_opaque_before_lacp_length_checks() {
    let registry = builtin::registry();
    for wire in [b"\x03\0\0\x01".as_slice(), b"\x02\x01", b"\x01\x02"] {
        let decoded = registry
            .codec("lacp")
            .unwrap()
            .decode(
                Bytes::copy_from_slice(wire),
                &DecodeContext {
                    parent: Some(crate::layer::Id::new("ethernet")),
                    registry: &registry,
                    network: None,
                    hop_limit: None,
                    discriminator: None,
                },
            )
            .unwrap();
        assert_eq!(decoded.layer.protocol_id().as_str(), "raw");
        assert_eq!(
            decoded.layer.field("bytes"),
            Some(Bytes::copy_from_slice(wire).into())
        );
    }
    assert!(
        registry
            .codec("lacp")
            .unwrap()
            .decode(
                Bytes::from_static(b"\x01\x01"),
                &DecodeContext {
                    parent: None,
                    registry: &registry,
                    network: None,
                    hop_limit: None,
                    discriminator: None,
                }
            )
            .is_err()
    );
}

#[test]
fn rtcp_reports_preserve_profile_extensions() {
    // https://datatracker.ietf.org/doc/html/rfc3550#section-6.4.3 checked 2026-10-25.
    let registry = builtin::registry();
    let mut compound = Vec::new();
    for (kind, base_length) in [(200, 24), (201, 4)] {
        for count in [0, 1] {
            let body_length = base_length + 24 * usize::from(count) + 4;
            let mut wire = vec![0x80 | count, kind];
            wire.extend_from_slice(&((body_length / 4) as u16).to_be_bytes());
            wire.resize(4 + body_length - 4, 0);
            wire.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
            preserve_wire(
                "rtcp",
                &wire,
                &[
                    ("packets[0].packet_type", kind.into()),
                    ("packets[0].count", count.into()),
                    (
                        "packets[0].data",
                        Bytes::from(
                            [
                                vec![0; base_length + 24 * usize::from(count)],
                                vec![0xde, 0xad, 0xbe, 0xef],
                            ]
                            .concat(),
                        )
                        .into(),
                    ),
                ],
            );
            compound.extend_from_slice(&wire);
        }
        let mut truncated = vec![0x81, kind];
        truncated.extend_from_slice(&((base_length / 4) as u16).to_be_bytes());
        truncated.resize(base_length + 4, 0);
        assert!(
            registry
                .codec("rtcp")
                .unwrap()
                .decode(
                    truncated.into(),
                    &DecodeContext {
                        parent: None,
                        registry: &registry,
                        network: None,
                        hop_limit: None,
                        discriminator: None,
                    }
                )
                .is_err()
        );
    }
    let expected = [(200_u8, 24), (201, 4)]
        .into_iter()
        .flat_map(|(kind, base)| {
            [0_u8, 1].map(|count| {
                field::Value::Object(record([
                    ("packet_type", kind.into()),
                    ("count", count.into()),
                    (
                        "data",
                        Bytes::from(
                            [
                                vec![0; base + 24 * usize::from(count)],
                                vec![0xde, 0xad, 0xbe, 0xef],
                            ]
                            .concat(),
                        )
                        .into(),
                    ),
                    ("padding", Bytes::new().into()),
                ]))
            })
        })
        .collect();
    preserve_wire(
        "rtcp",
        &compound,
        &[("packets", field::Value::List(expected))],
    );
}

#[test]
fn mqtt_persistent_sessions_require_a_client_identifier() {
    // https://docs.oasis-open.org/mqtt/mqtt/v3.1.1/os/mqtt-v3.1.1-os.html section 3.1.3.1 checked 2026-10-25.
    use crate::protocol::application::mqtt::Mqtt;
    let registry = builtin::registry();
    for (flags, client_id) in [
        (0, b"".as_slice()),
        (2, b""),
        (0, b"client"),
        (2, b"client"),
    ] {
        let valid = flags & 2 != 0 || !client_id.is_empty();
        let mut packet = Packet::new();
        packet.push(Mqtt {
            packet_type: 1,
            connect_flags: flags,
            keep_alive: 60,
            client_id: Bytes::copy_from_slice(client_id),
            ..Default::default()
        });
        let built = crate::build::Builder::new(registry.clone()).build(
            packet,
            Addresses::default(),
            Default::default(),
        );
        let mut wire = vec![
            0x10,
            (12 + client_id.len()) as u8,
            0,
            4,
            b'M',
            b'Q',
            b'T',
            b'T',
            4,
            flags,
            0,
            60,
            0,
            client_id.len() as u8,
        ];
        wire.extend_from_slice(client_id);
        let decoded = decode("mqtt", &wire);
        if !valid {
            assert!(built.is_err());
            assert!(decoded.is_err());
            continue;
        }
        assert_eq!(built.unwrap().bytes.as_ref(), wire);
        assert_fields(
            decoded.unwrap().layer.as_ref(),
            &[
                ("packet_type", 1_u8.into()),
                ("connect_flags", flags.into()),
                ("client_id", Bytes::copy_from_slice(client_id).into()),
                ("keep_alive", 60_u16.into()),
            ],
        );
    }
}

#[test]
fn mqtt_subscription_and_will_topics() {
    // https://docs.oasis-open.org/mqtt/mqtt/v3.1.1/os/mqtt-v3.1.1-os.html sections 3.1.3 and 4.7 checked 2026-10-25.
    fn sized(value: &[u8], wire: &mut Vec<u8>) {
        wire.extend_from_slice(&(value.len() as u16).to_be_bytes());
        wire.extend_from_slice(value);
    }
    for topic in [
        b"a/+/#".as_slice(),
        b"+",
        b"#",
        b"/+/",
        b"a+",
        b"a/#/b",
        b"a/##",
        b"",
    ] {
        let valid = matches!(topic, b"a/+/#" | b"+" | b"#" | b"/+/");
        for packet_type in [8, 10] {
            let mut body = vec![0, 1];
            sized(topic, &mut body);
            if packet_type == 8 {
                body.push(0);
            }
            let mut wire = vec![packet_type << 4 | 2, body.len() as u8];
            wire.extend(body);
            let decoded = decode("mqtt", &wire);
            if !valid {
                assert!(decoded.is_err(), "{topic:?}");
                continue;
            }
            assert_fields(
                decoded.unwrap().layer.as_ref(),
                &[
                    ("packet_type", packet_type.into()),
                    ("flags", 2_u8.into()),
                    ("packet_id", 1_u16.into()),
                    (
                        "subscriptions[0].topic",
                        Bytes::copy_from_slice(topic).into(),
                    ),
                ],
            );
        }
    }
    for topic in [b"will/topic".as_slice(), b"", b"will/+", b"will/#"] {
        let mut body = vec![0, 4, b'M', b'Q', b'T', b'T', 4, 6, 0, 60, 0, 0];
        sized(topic, &mut body);
        sized(b"payload", &mut body);
        let mut wire = vec![0x10, body.len() as u8];
        wire.extend(body);
        let decoded = decode("mqtt", &wire);
        if topic != b"will/topic" {
            assert!(decoded.is_err(), "{topic:?}");
            continue;
        }
        assert_fields(
            decoded.unwrap().layer.as_ref(),
            &[
                ("packet_type", 1_u8.into()),
                ("connect_flags", 6_u8.into()),
                ("will_topic", Bytes::from_static(b"will/topic").into()),
                ("will_payload", Bytes::from_static(b"payload").into()),
            ],
        );
    }
}

#[test]
fn malformed_resp_lines_and_modbus_ranges_are_refused() {
    let registry = builtin::registry();
    let context = DecodeContext {
        parent: None,
        registry: &registry,
        network: None,
        hop_limit: None,
        discriminator: None,
    };
    assert!(
        registry
            .codec("resp")
            .unwrap()
            .decode(Bytes::from_static(b"+a\rb\r\n"), &context)
            .is_err()
    );
    let mut packet = Packet::new();
    packet.push(crate::protocol::application::modbus_tcp::ModbusTcp {
        quantity: 126,
        ..Default::default()
    });
    assert!(
        crate::build::Builder::new(registry)
            .build(packet, Addresses::default(), Default::default())
            .is_err()
    );
}
