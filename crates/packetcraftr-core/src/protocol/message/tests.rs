// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
use crate::{
    codec::{Addresses, DecodeContext, EncodeContext, Mode},
    packet::Packet,
    protocol::builtin,
};
use bytes::Bytes;

fn round_trip(name: &str, wire: &[u8]) {
    round_trip_inner(name, wire, false);
}
fn round_trip_ipv6(name: &str, wire: &[u8]) {
    round_trip_inner(name, wire, true);
}
fn round_trip_inner(name: &str, wire: &[u8], ipv6: bool) {
    let network = ipv6.then(|| crate::codec::NetworkEnvelope {
        source: "2001:db8::1".parse().unwrap(),
        destination: "2001:db8::2".parse().unwrap(),
    });
    let registry = builtin::registry();
    let codec = registry.codec(name).unwrap();
    let decoded = codec
        .decode(
            Bytes::copy_from_slice(wire),
            &DecodeContext {
                parent: None,
                registry: &registry,
                network,
                hop_limit: None,
                discriminator: None,
            },
        )
        .unwrap();
    assert_eq!(decoded.layer.protocol_id().as_str(), name, "{name}");
    assert_eq!(decoded.consumed, wire.len());
    let mut packet = Packet::new();
    packet.push_boxed(decoded.layer);
    let addresses = network
        .map(|n| Addresses {
            source: Some(n.source),
            destination: Some(n.destination),
        })
        .unwrap_or_default();
    let context = EncodeContext {
        packet: &packet,
        index: 0,
        build_context: &addresses,
        mode: Mode::Strict,
        registry: &registry,
        child: None,
        remaining_packet_bytes: 65536,
    };
    let encoded = codec
        .encode(packet.layer(0).unwrap(), &[], &context)
        .unwrap();
    assert_eq!(encoded.prefix, wire, "{name}");
    let refused = EncodeContext {
        remaining_packet_bytes: wire.len().saturating_sub(1),
        ..context
    };
    assert!(
        codec
            .encode(packet.layer(0).unwrap(), &[], &refused)
            .is_err(),
        "budget {name}"
    );
}
#[test]
fn application_reference_vectors() {
    round_trip("mqtt", &[0x30, 4, 0, 1, b'a', b'x']);
    round_trip(
        "mqtt",
        &[0x10, 12, 0, 4, b'M', b'Q', b'T', b'T', 4, 2, 0, 60, 0, 0],
    );
    round_trip("coap", &[0x40, 1, 0x12, 0x34]);
    round_trip("amqp", &[8, 0, 0, 0, 0, 0, 0, 0xce]);
    round_trip("amqp", b"AMQP\0\0\x09\x01");
    round_trip("resp", b"*2\r\n$3\r\nGET\r\n$1\r\nx\r\n");
    round_trip(
        "memcached",
        &[
            0x80, 10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ],
    );
    round_trip(
        "ssdp",
        b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n\r\n",
    );
}
#[test]
fn truncated_and_unsupported_packets_preserve_bytes() {
    let reg = builtin::registry();
    let context = DecodeContext {
        parent: None,
        registry: &reg,
        network: None,
        hop_limit: None,
        discriminator: None,
    };
    for (name, wire) in [
        ("mqtt", vec![0x30, 10, 0]),
        ("coap", vec![0x49, 1, 0, 0]),
        ("amqp", vec![1, 0, 0, 0, 0, 0, 0, 0]),
        ("memcached", vec![0x80, 0]),
    ] {
        assert!(
            reg.codec(name)
                .unwrap()
                .decode(wire.into(), &context)
                .is_err(),
            "{name}"
        );
    }
    let wire = Bytes::from_static(b"get key\r\n");
    let raw = reg
        .codec("memcached")
        .unwrap()
        .decode(wire.clone(), &context)
        .unwrap();
    assert_eq!(raw.layer.protocol_id().as_str(), "raw");
    assert_eq!(raw.consumed, wire.len());
    assert_eq!(
        raw.layer.field("bytes"),
        Some(crate::field::Value::Bytes(wire))
    );
}
#[test]
fn mqtt_fields_are_editable() {
    let reg = builtin::registry();
    let context = DecodeContext {
        parent: None,
        registry: &reg,
        network: None,
        hop_limit: None,
        discriminator: None,
    };
    let mut decoded = reg
        .codec("mqtt")
        .unwrap()
        .decode(Bytes::from_static(&[0x30, 4, 0, 1, b'a', b'x']), &context)
        .unwrap();
    assert_eq!(
        decoded.layer.field("packet_type"),
        Some(crate::field::Value::Unsigned(3))
    );
    assert_eq!(
        decoded.layer.field("topic"),
        Some(crate::field::Value::Bytes(Bytes::from_static(b"a")))
    );
    assert_eq!(
        decoded.layer.field("payload"),
        Some(crate::field::Value::Bytes(Bytes::from_static(b"x")))
    );
    decoded
        .layer
        .set_field(
            "topic",
            crate::field::Value::Bytes(Bytes::from_static(b"next")),
        )
        .unwrap();
    assert_eq!(
        decoded.layer.field("topic"),
        Some(crate::field::Value::Bytes(Bytes::from_static(b"next")))
    );
    let mut packet = Packet::new();
    packet.push_boxed(decoded.layer);
    let built = crate::build::Builder::new(reg)
        .build(packet, Addresses::default(), Default::default())
        .unwrap();
    // MQTT 3.1.1 section 3.3, checked 2026-10-25.
    // https://docs.oasis-open.org/mqtt/mqtt/v3.1.1/os/mqtt-v3.1.1-os.html
    assert_eq!(built.bytes.as_ref(), b"\x30\x07\0\x04nextx");
}

#[test]
fn protocol_expansion_reference_vectors() {
    round_trip("mqtt", &[48, 4, 0, 1, 97, 120]);
    round_trip("coap", &[64, 1, 18, 52, 180, 116, 101, 115, 116]);
    round_trip("amqp", &[8, 0, 0, 0, 0, 0, 0, 206]);
    round_trip(
        "resp",
        &[
            42, 50, 13, 10, 36, 51, 13, 10, 71, 69, 84, 13, 10, 36, 49, 13, 10, 120, 13, 10,
        ],
    );
    round_trip(
        "memcached",
        &[
            128, 10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ],
    );
    round_trip(
        "ssdp",
        &[
            77, 45, 83, 69, 65, 82, 67, 72, 32, 42, 32, 72, 84, 84, 80, 47, 49, 46, 49, 13, 10, 72,
            79, 83, 84, 58, 32, 50, 51, 57, 46, 50, 53, 53, 46, 50, 53, 53, 46, 50, 53, 48, 58, 49,
            57, 48, 48, 13, 10, 13, 10,
        ],
    );
    round_trip("eap", &[1, 1, 0, 10, 1, 97, 108, 105, 99, 101]);
    round_trip(
        "lacp",
        &[
            1, 1, 1, 20, 128, 0, 2, 0, 0, 0, 0, 1, 0, 1, 128, 0, 0, 1, 63, 0, 0, 0, 2, 20, 128, 0,
            2, 0, 0, 0, 0, 2, 0, 1, 128, 0, 0, 2, 63, 0, 0, 0, 3, 16, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ],
    );
    round_trip(
        "cdp",
        &[2, 180, 188, 236, 0, 1, 0, 10, 115, 119, 105, 116, 99, 104],
    );
    round_trip("ppp_lcp", &[1, 1, 0, 8, 1, 4, 5, 220]);
    round_trip("ppp_ipcp", &[1, 1, 0, 10, 3, 6, 192, 0, 2, 1]);
    round_trip("ppp_ipv6cp", &[1, 1, 0, 14, 1, 10, 2, 0, 0, 0, 0, 0, 0, 1]);
    round_trip(
        "bgp",
        &[
            255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 0, 29,
            1, 4, 252, 0, 0, 90, 192, 0, 2, 1, 0,
        ],
    );
    round_trip(
        "ospfv2",
        &[
            2, 1, 0, 44, 192, 0, 2, 1, 0, 0, 0, 0, 58, 157, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255,
            255, 0, 0, 10, 2, 1, 0, 0, 0, 40, 0, 0, 0, 0, 0, 0, 0, 0,
        ],
    );
    round_trip_ipv6(
        "ospfv3",
        &[
            3, 1, 0, 36, 192, 0, 2, 1, 0, 0, 0, 0, 221, 160, 0, 0, 0, 0, 0, 1, 1, 0, 0, 19, 0, 10,
            0, 40, 0, 0, 0, 0, 0, 0, 0, 0,
        ],
    );
    round_trip(
        "ripv2",
        &[
            2, 2, 0, 0, 0, 2, 0, 0, 198, 51, 100, 0, 255, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 2,
        ],
    );
    round_trip(
        "ripng",
        &[
            2, 1, 0, 0, 32, 1, 13, 184, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 64, 2,
        ],
    );
    round_trip("pim", &[32, 0, 223, 147, 0, 1, 0, 2, 0, 105]);
    round_trip(
        "snmp",
        &[
            48, 38, 2, 1, 1, 4, 6, 112, 117, 98, 108, 105, 99, 160, 25, 2, 1, 1, 2, 1, 0, 2, 1, 0,
            48, 14, 48, 12, 6, 8, 43, 6, 1, 2, 1, 1, 1, 0, 5, 0,
        ],
    );
    round_trip(
        "radius",
        &[
            1, 7, 0, 27, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 7, 97, 108, 105, 99,
            101,
        ],
    );
    round_trip("ldap", &[48, 12, 2, 1, 1, 96, 7, 2, 1, 3, 4, 0, 128, 0]);
    round_trip(
        "netflowv5",
        &[
            0, 5, 0, 1, 0, 0, 3, 232, 101, 83, 241, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 192, 0,
            2, 1, 198, 51, 100, 1, 192, 0, 2, 254, 0, 1, 0, 2, 0, 0, 0, 10, 0, 0, 3, 32, 0, 0, 0,
            100, 0, 0, 0, 200, 156, 64, 1, 187, 0, 16, 6, 0, 252, 0, 252, 1, 24, 24, 0, 0,
        ],
    );
    round_trip(
        "ipfix",
        &[
            0, 10, 0, 36, 101, 83, 241, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 2, 0, 12, 1, 0, 0, 1, 0, 8,
            0, 4, 1, 0, 0, 8, 192, 0, 2, 1,
        ],
    );
    round_trip(
        "sflow",
        &[
            0, 0, 0, 5, 0, 0, 0, 1, 192, 0, 2, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 3, 232, 0, 0, 0, 1,
            0, 0, 0, 1, 0, 0, 0, 56, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 100, 0, 0, 0, 100, 0, 0, 0,
            0, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 16, 0, 0, 0, 1, 0, 0, 0,
            64, 0, 0, 0, 0, 0, 0, 0, 0,
        ],
    );
    round_trip(
        "sip",
        &[
            79, 80, 84, 73, 79, 78, 83, 32, 115, 105, 112, 58, 115, 101, 114, 118, 105, 99, 101,
            32, 83, 73, 80, 47, 50, 46, 48, 13, 10, 67, 83, 101, 113, 58, 32, 49, 32, 79, 80, 84,
            73, 79, 78, 83, 13, 10, 67, 111, 110, 116, 101, 110, 116, 45, 76, 101, 110, 103, 116,
            104, 58, 32, 48, 13, 10, 13, 10,
        ],
    );
    round_trip(
        "rtsp",
        &[
            79, 80, 84, 73, 79, 78, 83, 32, 42, 32, 82, 84, 83, 80, 47, 49, 46, 48, 13, 10, 67, 83,
            101, 113, 58, 32, 49, 13, 10, 67, 111, 110, 116, 101, 110, 116, 45, 76, 101, 110, 103,
            116, 104, 58, 32, 48, 13, 10, 13, 10,
        ],
    );
    round_trip("rtp", &[128, 96, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 1]);
    round_trip(
        "rtcp",
        &[
            128, 200, 0, 6, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ],
    );
    round_trip(
        "stun",
        &[
            1, 1, 0, 12, 33, 18, 164, 66, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 32, 0, 8, 0, 1,
            245, 35, 225, 18, 166, 67,
        ],
    );
    round_trip(
        "dtls",
        &[
            22, 254, 253, 0, 0, 0, 0, 0, 0, 0, 0, 0, 12, 14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ],
    );
    round_trip("modbus_tcp", &[0, 1, 0, 0, 0, 6, 1, 3, 0, 0, 0, 2]);
    round_trip("bacnet_ip", &[129, 10, 0, 8, 1, 0, 16, 8]);
    round_trip("dnp3", &[5, 100, 5, 192, 1, 0, 0, 4, 233, 33]);
    round_trip(
        "ethernet_ip",
        &[
            101, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0,
        ],
    );
    round_trip("iec104", &[104, 4, 7, 0, 0, 0]);
    round_trip(
        "opcua_tcp",
        &[
            72, 69, 76, 70, 56, 0, 0, 0, 0, 0, 0, 0, 0, 32, 0, 0, 0, 32, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 24, 0, 0, 0, 111, 112, 99, 46, 116, 99, 112, 58, 47, 47, 108, 111, 99, 97, 108, 104,
            111, 115, 116, 58, 52, 56, 52, 48,
        ],
    );
}

#[test]
fn ipv6_ospf_survives_authentication_header() {
    let registry = builtin::registry();
    let mut packet = Packet::new();
    packet.push(crate::protocol::link::Ethernet::default());
    packet.push(crate::protocol::network::Ipv6 {
        source: "2001:db8::1".parse().unwrap(),
        destination: "2001:db8::2".parse().unwrap(),
        ..Default::default()
    });
    packet.push(crate::protocol::tunnel::Ah::default());
    packet.push(crate::protocol::network::ospfv3::Ospfv3::default());
    let built = crate::build::Builder::new(registry.clone())
        .build(packet, Addresses::default(), Default::default())
        .unwrap();
    let frame =
        crate::frame::Frame::without_timestamp(crate::frame::LinkType::ETHERNET, built.bytes)
            .unwrap();
    let decoded = crate::decode::Dissector::new(registry)
        .decode(frame, Default::default())
        .unwrap();
    assert!(
        decoded
            .packet
            .get::<crate::protocol::network::ospfv3::Ospfv3>()
            .is_some(),
        "{:?}",
        decoded.diagnostics
    );
}

#[test]
fn coalesced_packet_messages_rebuild_without_losing_tail() {
    let registry = builtin::registry();
    let mut packet = Packet::new();
    packet.push(crate::protocol::link::Ethernet::default());
    packet.push(crate::protocol::network::Ipv4::default());
    packet.push(crate::protocol::transport::Tcp {
        destination_port: 1883,
        ..Default::default()
    });
    packet.push(crate::protocol::application::mqtt::Mqtt::default());
    packet.push(crate::protocol::application::mqtt::Mqtt::default());
    let builder = crate::build::Builder::new(registry.clone());
    let built = builder
        .build(packet, Addresses::default(), Default::default())
        .unwrap();
    let frame = crate::frame::Frame::without_timestamp(
        crate::frame::LinkType::ETHERNET,
        built.bytes.clone(),
    )
    .unwrap();
    let decoded = crate::decode::Dissector::new(registry)
        .decode(frame, Default::default())
        .unwrap();
    assert_eq!(
        decoded
            .packet
            .iter()
            .filter(|p| p.protocol_id().as_str() == "mqtt")
            .count(),
        2
    );
    let rebuilt = builder
        .build(decoded.packet, Addresses::default(), Default::default())
        .unwrap();
    assert_eq!(built.bytes, rebuilt.bytes);
}

#[test]
fn captures_convert_to_editable_documents_and_rebuild() {
    let manifest: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../../examples/captures/protocols.manifest.json"
    ))
    .unwrap();
    for entry in manifest["protocols"].as_array().unwrap() {
        let name = entry["protocol"].as_str().unwrap();
        let registry = std::sync::Arc::new(
            crate::protocol::builtin::registry_with(|builder| {
                if let Some(binding) = entry["decode_as"].as_str() {
                    let (selector, child) = binding.split_once(':').unwrap();
                    let port = selector.split_once('=').unwrap().1.parse::<u64>().unwrap();
                    builder.bind(
                        "udp",
                        port,
                        crate::protocol::BuiltinProtocol::from_name(child)
                            .unwrap()
                            .as_str(),
                        i32::MAX,
                    )?;
                }
                Ok(())
            })
            .unwrap(),
        );
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../examples/captures")
            .join(entry["capture"].as_str().unwrap());
        let capture = std::fs::read(path).unwrap();
        let mut reader = crate::capture_file::Reader::new(&capture[..]).unwrap();
        let frame = reader.next_frame().unwrap().unwrap();
        let original = frame.bytes().clone();
        let decoded = crate::decode::Dissector::new(registry.clone())
            .decode(frame, Default::default())
            .unwrap();
        assert!(
            decoded
                .packet
                .iter()
                .any(|p| p.protocol_id().as_str() == name),
            "{name}: {:?}",
            decoded.diagnostics
        );
        let doc = crate::document::Packet::from_packet(&decoded.packet);
        let json = serde_json::to_vec(&doc).unwrap();
        let doc = crate::document::Packet::parse(
            std::str::from_utf8(&json).unwrap(),
            crate::document::Format::Json,
            json.len(),
        )
        .unwrap();
        let packet = doc.to_packet(&registry, 64).unwrap();
        let rebuilt = crate::build::Builder::new(registry)
            .build(packet, Addresses::default(), Default::default())
            .unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(rebuilt.bytes, original, "{name}");
    }
}

#[test]
fn noncanonical_ber_and_unknown_extensions_preserve_wire() {
    let registry = builtin::registry();
    let context = DecodeContext {
        parent: None,
        registry: &registry,
        network: None,
        hop_limit: None,
        discriminator: None,
    };
    let bytes = Bytes::from_static(&[0x30, 0x80, 0, 0]);
    let decoded = registry
        .codec("ldap")
        .unwrap()
        .decode(bytes.clone(), &context)
        .unwrap();
    assert_eq!(decoded.layer.protocol_id().as_str(), "raw");
    assert_eq!(
        decoded.layer.field("bytes"),
        Some(crate::field::Value::Bytes(bytes))
    );
    round_trip("coap", &[0x40, 1, 0, 1, 0xb1, b'x', 0x01, b'y']);
    round_trip("cdp", &[2, 180, 253, 99, 0, 99, 0, 5, 128]);
}

#[test]
fn reference_packet_prefixes_are_bounded() {
    let registry = builtin::registry();
    let manifest: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../../examples/captures/protocols.manifest.json"
    ))
    .unwrap();
    let context = DecodeContext {
        parent: None,
        registry: &registry,
        network: None,
        hop_limit: None,
        discriminator: None,
    };
    for row in manifest["protocols"].as_array().unwrap() {
        let name = row["protocol"].as_str().unwrap();
        let bytes = crate::layer::parse_hex(row["wire_hex"].as_str().unwrap()).unwrap();
        for len in 0..bytes.len() {
            if let Ok(decoded) = registry
                .codec(name)
                .unwrap()
                .decode(Bytes::copy_from_slice(&bytes[..len]), &context)
            {
                assert!(decoded.consumed <= len, "{name}: prefix {len}");
                assert!(
                    decoded.consumed + decoded.payload_len <= len,
                    "{name}: prefix {len}"
                );
            }
        }
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
