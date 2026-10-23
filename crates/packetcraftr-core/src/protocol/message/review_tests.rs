// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use bytes::Bytes;

use crate::{
    codec::{Addresses, DecodeContext, EncodeContext, Mode},
    document, field,
    frame::{Frame, LinkType},
    layer::Layer,
    packet::Packet,
    protocol::{
        application::{dtls::Dtls, sflow::Sflow, sip::Sip},
        builtin,
        link::Ethernet,
        network::Ipv4,
        transport::{Tcp, Udp},
    },
};

use super::{Records, record};

#[test]
fn review_sip_udp_without_content_length_uses_the_datagram() {
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
fn review_sip_tcp_still_requires_content_length() {
    let mut framer = crate::protocol::framing::Framer::new("sip");
    assert!(
        framer
            .progress(b"OPTIONS sip:service SIP/2.0\r\n\r\n", 65536)
            .is_err()
    );
}

#[test]
fn review_ospfv2_preserves_the_separate_authentication_digest() {
    let manifest: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../../examples/captures/protocols.manifest.json"
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
fn review_dtls_document_rejects_oversized_fragment_offsets_without_panicking() {
    let fragment = field::Value::Object(record([
        ("message_type", 1_u8.into()),
        ("length", 1_u8.into()),
        ("message_sequence", 0_u8.into()),
        ("offset", u64::MAX.into()),
        ("data", Bytes::from_static(b"x").into()),
    ]));
    let mut packet = Packet::new();
    packet.push(Dtls {
        records: Records(vec![record([
            ("content_type", 22_u8.into()),
            ("epoch", 0_u8.into()),
            ("sequence", 0_u8.into()),
            ("handshakes", field::Value::List(vec![fragment])),
        ])]),
    });
    let json = serde_json::to_string(&document::Packet::from_packet(&packet)).unwrap();
    let document = document::Packet::parse(&json, document::Format::Json, json.len()).unwrap();
    let registry = builtin::registry();
    let packet = document.to_packet(&registry, 16).unwrap();
    assert!(
        crate::build::Builder::new(registry)
            .build(packet, Addresses::default(), Default::default())
            .is_err()
    );
}

#[test]
fn review_sflow_sample_members_support_editing_and_projection() {
    let registry = builtin::registry();
    let json = include_str!("../../../../../examples/documents/packet-sflow.json");
    let document = document::Packet::parse(json, document::Format::Json, json.len()).unwrap();
    let mut packet = document.to_packet(&registry, 64).unwrap();
    let sflow = packet.get_mut::<Sflow>().unwrap();
    for name in [
        "sampling_rate",
        "sample_pool",
        "drops",
        "input",
        "output",
        "source_type",
        "source_index",
        "input_format",
        "output_format",
        "padding",
    ] {
        let path: field::Path = format!("samples[0].{name}").parse().unwrap();
        assert!(
            path.schema(sflow.schema()).is_some(),
            "missing sample member {name}"
        );
    }
    for name in ["format", "data", "padding"] {
        let path: field::Path = format!("samples[0].records[0].{name}").parse().unwrap();
        assert!(
            path.schema(sflow.schema()).is_some(),
            "missing record member {name}"
        );
    }
    let path: field::Path = "samples[0].sampling_rate".parse().unwrap();
    sflow.set_field_path(&path, 200_u32.into()).unwrap();
    let built = crate::build::Builder::new(registry.clone())
        .build(packet, Addresses::default(), Default::default())
        .unwrap();
    let decoded = crate::decode::Dissector::new(registry.clone())
        .decode(
            Frame::without_timestamp(LinkType::ETHERNET, built.bytes).unwrap(),
            Default::default(),
        )
        .unwrap();
    let projection =
        crate::filter::Projection::compile(["sflow#1.samples[0].sampling_rate"], &registry)
            .unwrap();
    assert_eq!(
        projection
            .values(&crate::filter::Context::frame(&decoded, 1), 4096)
            .unwrap(),
        vec![Some(field::Value::Unsigned(200))]
    );
}

#[test]
fn review_strict_build_checks_sip_and_rtsp_transport_framing() {
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
fn review_large_cdp_checksum_round_trips_without_overflow() {
    let mut packet = Packet::new();
    packet.push(crate::protocol::link::cdp::Cdp {
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
    review_round_trip("cdp", &built.bytes);
}

fn review_round_trip(name: &str, wire: &[u8]) {
    let registry = builtin::registry();
    let codec = registry.codec(name).unwrap();
    let decoded = codec
        .decode(
            Bytes::copy_from_slice(wire),
            &DecodeContext {
                parent: None,
                registry: &registry,
                network: None,
                hop_limit: None,
                discriminator: None,
            },
        )
        .unwrap();
    assert_eq!(decoded.layer.protocol_id().as_str(), name);
    assert_eq!(decoded.consumed, wire.len());
    let mut packet = Packet::new();
    packet.push_boxed(decoded.layer);
    let built = crate::build::Builder::new(registry)
        .build(packet, Addresses::default(), Default::default())
        .unwrap();
    assert_eq!(built.bytes.as_ref(), wire);
}

#[test]
fn review_radius_padding_is_separate_from_attributes() {
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
fn review_ethernet_ip_errors_preserve_opaque_command_data() {
    for command in [0x65_u16, 0x6f, 0x70] {
        for data in [&[][..], &[0xa5, 0x5a][..]] {
            let mut wire = Vec::from(command.to_le_bytes());
            wire.extend_from_slice(&(data.len() as u16).to_le_bytes());
            wire.extend_from_slice(&[0; 4]);
            wire.extend_from_slice(&100_u32.to_le_bytes());
            wire.extend_from_slice(&[0; 12]);
            wire.extend_from_slice(data);
            review_round_trip("ethernet_ip", &wire);
        }
    }
}

#[test]
fn review_ipfix_options_template_withdrawals_round_trip() {
    for templates in [vec![256_u16], vec![256, 257], vec![3]] {
        let mut wire = vec![0, 10];
        wire.extend_from_slice(&(20 + templates.len() as u16 * 4).to_be_bytes());
        wire.extend_from_slice(&[0; 12]);
        wire.extend_from_slice(&3_u16.to_be_bytes());
        wire.extend_from_slice(&(4 + templates.len() as u16 * 4).to_be_bytes());
        for id in templates {
            wire.extend_from_slice(&id.to_be_bytes());
            wire.extend_from_slice(&[0, 0]);
        }
        review_round_trip("ipfix", &wire);
    }
}

#[test]
fn review_ipfix_and_dtls_nested_fields_support_editing_and_projection() {
    for (name, json, path, value, members) in [
        (
            "ipfix",
            include_str!("../../../../../examples/documents/packet-ipfix.json"),
            "sets[0].records[0].fields[0].length",
            8_u64,
            vec![
                "sets[0].records[0].template_id",
                "sets[0].records[0].scope_count",
                "sets[0].records[0].fields[0].element_id",
                "sets[0].records[0].fields[0].enterprise",
            ],
        ),
        (
            "dtls",
            include_str!("../../../../../examples/documents/packet-dtls.json"),
            "records[0].handshakes[0].message_sequence",
            2_u64,
            vec![
                "records[0].handshakes[0].message_type",
                "records[0].handshakes[0].length",
                "records[0].handshakes[0].offset",
                "records[0].handshakes[0].data",
            ],
        ),
    ] {
        let registry = std::sync::Arc::new(
            builtin::registry_with(|builder| {
                if name == "dtls" {
                    builder.bind("udp", 5684, "dtls", i32::MAX)?;
                }
                Ok(())
            })
            .unwrap(),
        );
        let document = document::Packet::parse(json, document::Format::Json, json.len()).unwrap();
        let mut packet = document.to_packet(&registry, 64).unwrap();
        let index = packet
            .iter()
            .position(|layer| layer.protocol_id().as_str() == name)
            .unwrap();
        let layer = packet.layer_mut(index).unwrap();
        for member in members {
            assert!(
                member
                    .parse::<field::Path>()
                    .unwrap()
                    .schema(layer.schema())
                    .is_some(),
                "{name}.{member}"
            );
        }
        layer
            .set_field_path(&path.parse().unwrap(), value.into())
            .unwrap();
        if let Some(tcp) = packet.get_mut::<Tcp>() {
            tcp.checksum = field::WireValue::Auto;
        }
        if let Some(udp) = packet.get_mut::<Udp>() {
            udp.checksum = field::WireValue::Auto;
        }
        let built = crate::build::Builder::new(registry.clone())
            .build(packet, Addresses::default(), Default::default())
            .unwrap();
        let decoded = crate::decode::Dissector::new(registry.clone())
            .decode(
                Frame::without_timestamp(LinkType::ETHERNET, built.bytes).unwrap(),
                Default::default(),
            )
            .unwrap();
        let column = format!("{name}#1.{path}");
        let projection = crate::filter::Projection::compile([column.as_str()], &registry).unwrap();
        assert_eq!(
            projection
                .values(&crate::filter::Context::frame(&decoded, 1), 4096)
                .unwrap(),
            vec![Some(value.into())]
        );
    }
}

#[test]
fn review_unsupported_stream_tail_survives_strict_rebuild() {
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
        decoded.packet.layer(3).unwrap().protocol_id().as_str(),
        "mqtt"
    );
    assert_eq!(
        decoded.packet.layer(4).unwrap().protocol_id().as_str(),
        "raw"
    );
    let rebuilt = builder
        .build(decoded.packet, Addresses::default(), Default::default())
        .unwrap();
    assert_eq!(rebuilt.bytes, built.bytes);
}

#[test]
fn review_datagram_messages_reject_unframed_opaque_tails() {
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
fn review_folded_sip_and_rtsp_headers_preserve_bytes_and_frame_lengths() {
    for (name, start) in [
        ("sip", "OPTIONS sip:service SIP/2.0"),
        ("rtsp", "OPTIONS * RTSP/1.0"),
    ] {
        let wire = format!("{start}\r\nSubject: a\r\n b\r\nContent-Length:\r\n\t4\r\n\r\nbody");
        review_round_trip(name, wire.as_bytes());
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
fn review_amqp_content_headers_require_complete_property_flags() {
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
        assert_eq!(
            crate::build::Builder::new(builtin::registry())
                .build(packet, Addresses::default(), Default::default())
                .is_ok(),
            valid
        );
        let mut wire = vec![2, 0, 1];
        wire.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        wire.extend_from_slice(&payload);
        wire.push(0xce);
        let registry = builtin::registry();
        assert_eq!(
            registry
                .codec("amqp")
                .unwrap()
                .decode(
                    wire.into(),
                    &DecodeContext {
                        parent: None,
                        registry: &registry,
                        network: None,
                        hop_limit: None,
                        discriminator: None,
                    }
                )
                .is_ok(),
            valid
        );
    }
}

#[test]
fn review_resp_payloads_support_typed_edits_filters_and_projection() {
    use crate::protocol::application::resp::{Resp, RespValue};
    for (value, path, replacement, literal) in [
        (
            RespValue::Simple(Bytes::from_static(b"OK")),
            "value.data",
            Bytes::from_static(b"NEXT").into(),
            "b\"NEXT\"",
        ),
        (
            RespValue::Integer(7),
            "value.data",
            field::Value::Signed(9),
            "9",
        ),
        (
            RespValue::Array(Some(vec![RespValue::Simple(Bytes::from_static(b"OK"))])),
            "value.data[0].data",
            Bytes::from_static(b"NEXT").into(),
            "b\"NEXT\"",
        ),
    ] {
        let registry = builtin::registry();
        let mut resp = Resp { value };
        resp.set_field_path(&path.parse().unwrap(), replacement.clone())
            .unwrap();
        let mut packet = Packet::new();
        packet.push(Ethernet::default());
        packet.push(Ipv4::default());
        packet.push(Tcp {
            destination_port: 6379,
            ..Default::default()
        });
        packet.push(resp);
        let built = crate::build::Builder::new(registry.clone())
            .build(packet, Addresses::default(), Default::default())
            .unwrap();
        let decoded = crate::decode::Dissector::new(registry.clone())
            .decode(
                Frame::without_timestamp(LinkType::ETHERNET, built.bytes).unwrap(),
                Default::default(),
            )
            .unwrap();
        let column = format!("resp#1.{path}");
        let projection = crate::filter::Projection::compile([column.as_str()], &registry).unwrap();
        let context = crate::filter::Context::frame(&decoded, 1);
        assert_eq!(
            projection.values(&context, 4096).unwrap(),
            vec![Some(replacement)]
        );
        assert!(
            crate::filter::Filter::compile(
                &format!("{column} == {literal}"),
                &registry,
                Default::default()
            )
            .unwrap()
            .matches(&context)
            .unwrap()
        );
        if path.contains("[0]") {
            let projection =
                crate::filter::Projection::compile(["resp.value.data[*].data"], &registry).unwrap();
            assert_eq!(
                projection.values(&context, 4096).unwrap(),
                vec![Some(field::Value::List(vec![
                    Bytes::from_static(b"NEXT").into()
                ]))]
            );
        }
    }
}

#[test]
fn review_bacnet_segment_ack_requires_its_window_size() {
    let ack = b"\x40\x01\x02\x01";
    for len in 0..=ack.len() {
        let registry = builtin::registry();
        let mut packet = Packet::new();
        packet.push(crate::protocol::application::bacnet_ip::BacnetIp {
            data: Bytes::copy_from_slice(&ack[..len]),
            ..Default::default()
        });
        assert_eq!(
            crate::build::Builder::new(registry.clone())
                .build(packet, Addresses::default(), Default::default())
                .is_ok(),
            len == 4
        );
        let mut wire = vec![0x81, 10, 0, (6 + len) as u8, 1, 0];
        wire.extend_from_slice(&ack[..len]);
        assert_eq!(
            registry
                .codec("bacnet_ip")
                .unwrap()
                .decode(
                    wire.into(),
                    &DecodeContext {
                        parent: None,
                        registry: &registry,
                        network: None,
                        hop_limit: None,
                        discriminator: None,
                    }
                )
                .is_ok(),
            len == 4
        );
    }
}

#[test]
fn review_sip_udp_preserves_excess_bytes_after_declared_body() {
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
fn review_outer_ethernet_padding_does_not_extend_datagram_framing() {
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
fn review_interleaved_rtsp_layout_only_contains_binary_fields() {
    let registry = builtin::registry();
    let mut packet = Packet::new();
    packet.push(crate::protocol::application::rtsp::Rtsp {
        interleaved: true,
        channel: 7,
        body: Bytes::from_static(b"\r\n\r\n"),
        ..Default::default()
    });
    let built = crate::build::Builder::new(registry.clone())
        .build(packet, Addresses::default(), Default::default())
        .unwrap();
    let fields = &built.layout.layer(0).unwrap().fields;
    assert_eq!(
        fields.iter().map(|field| field.name).collect::<Vec<_>>(),
        ["interleaved", "channel", "body"]
    );
    assert_eq!(fields[1].range, crate::layout::ByteRange::new(1, 2));
    assert_eq!(fields[2].range, crate::layout::ByteRange::new(4, 8));
    let decoded = registry
        .codec("rtsp")
        .unwrap()
        .decode(
            built.bytes,
            &DecodeContext {
                parent: None,
                registry: &registry,
                network: None,
                hop_limit: None,
                discriminator: None,
            },
        )
        .unwrap();
    assert_eq!(decoded.fields, *fields);
}

#[test]
fn review_other_slow_protocols_remain_opaque_before_lacp_length_checks() {
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
fn review_rtsp_and_sip_methods_accept_the_token_grammar() {
    for (name, version) in [("rtsp", "RTSP/1.0"), ("sip", "SIP/2.0")] {
        for method in ["GET_PARAMETER", "SET_PARAMETER", "custom_method2"] {
            let wire = format!("{method} * {version}\r\nContent-Length: 0\r\n\r\n");
            review_round_trip(name, wire.as_bytes());
        }
    }
}

#[test]
fn review_rtcp_reports_preserve_profile_extensions() {
    let registry = builtin::registry();
    let mut compound = Vec::new();
    for (kind, base_length) in [(200, 24), (201, 4)] {
        for count in [0, 1] {
            let body_length = base_length + 24 * usize::from(count) + 4;
            let mut wire = vec![0x80 | count, kind];
            wire.extend_from_slice(&((body_length / 4) as u16).to_be_bytes());
            wire.resize(4 + body_length - 4, 0);
            wire.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
            review_round_trip("rtcp", &wire);
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
    review_round_trip("rtcp", &compound);
}
