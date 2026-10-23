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
