// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
use bytes::Bytes;

use crate::{
    codec::{Addresses, DecodeContext, Decoded, EncodeContext, Mode},
    document, field,
    frame::{Frame, LinkType},
    layer::Layer,
    packet::Packet,
    protocol::{
        application::{dtls::Dtls, sflow::Sflow, sip::Sip},
        builtin,
        framing::Framer,
        link::Ethernet,
        network::Ipv4,
        transport::{Tcp, Udp},
    },
};

use super::{Records, record};

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
    let raw = reg
        .codec("memcached")
        .unwrap()
        .decode(Bytes::from_static(b"get key\r\n"), &context)
        .unwrap();
    assert_eq!(raw.layer.protocol_id().as_str(), "raw");
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
fn ospfv2_preserves_the_separate_authentication_digest() {
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
fn dtls_document_rejects_oversized_fragment_offsets_without_panicking() {
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
fn sflow_sample_members_support_editing_and_projection() {
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
fn large_cdp_checksum_round_trips_without_overflow() {
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
    builder_round_trip("cdp", &built.bytes);
}

fn builder_round_trip(name: &str, wire: &[u8]) {
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
            builder_round_trip("ethernet_ip", &wire);
        }
    }
}

#[test]
fn ipfix_options_template_withdrawals_round_trip() {
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
        builder_round_trip("ipfix", &wire);
    }
}

#[test]
fn ipfix_and_dtls_nested_fields_support_editing_and_projection() {
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
    for (name, start) in [
        ("sip", "OPTIONS sip:service SIP/2.0"),
        ("rtsp", "OPTIONS * RTSP/1.0"),
    ] {
        let wire = format!("{start}\r\nSubject: a\r\n b\r\nContent-Length:\r\n\t4\r\n\r\nbody");
        builder_round_trip(name, wire.as_bytes());
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
fn amqp_content_headers_require_complete_property_flags() {
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
fn resp_payloads_support_typed_edits_filters_and_projection() {
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
fn bacnet_segment_ack_requires_its_window_size() {
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
fn interleaved_rtsp_layout_only_contains_binary_fields() {
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
fn rtsp_and_sip_methods_accept_the_token_grammar() {
    for (name, version) in [("rtsp", "RTSP/1.0"), ("sip", "SIP/2.0")] {
        for method in ["GET_PARAMETER", "SET_PARAMETER", "custom_method2"] {
            let wire = format!("{method} * {version}\r\nContent-Length: 0\r\n\r\n");
            builder_round_trip(name, wire.as_bytes());
        }
    }
}

#[test]
fn rtcp_explicit_padding_preserves_report_data_boundaries() {
    use crate::protocol::application::rtcp::Rtcp;

    let registry = builtin::registry();
    let report_data = Bytes::from_static(b"\x00\x00\x00\x01\xde\xad\xbe\xef");
    for (padding, valid) in [
        (Bytes::from_static(b"\x00\x00\x00\x08"), false),
        (Bytes::from_static(b"\x00\x00\x00\x00"), false),
        (Bytes::from(vec![4; 260]), false),
        (Bytes::from_static(b"\x00\x00\x00\x04"), true),
        (Bytes::from(vec![252; 252]), true),
        (Bytes::new(), true),
    ] {
        let rtcp = Rtcp {
            packets: Records(vec![record([
                ("packet_type", 201u8.into()),
                ("count", 0u8.into()),
                ("data", report_data.clone().into()),
                ("padding", padding.clone().into()),
            ])]),
        };
        let expected = rtcp.field("packets");
        let mut packet = Packet::new();
        packet.push(rtcp);
        let result = crate::build::Builder::new(registry.clone()).build(
            packet,
            Addresses::default(),
            Default::default(),
        );
        if !valid {
            assert!(result.is_err(), "padding length {}", padding.len());
            continue;
        }
        let built = result.unwrap();
        assert_eq!(built.packet.layer(0).unwrap().field("packets"), expected);
        let mut wire = vec![if padding.is_empty() { 0x80 } else { 0xa0 }, 201];
        wire.extend_from_slice(&(((report_data.len() + padding.len()) / 4) as u16).to_be_bytes());
        wire.extend_from_slice(&report_data);
        wire.extend_from_slice(&padding);
        assert_eq!(built.bytes.as_ref(), wire);
        builder_round_trip("rtcp", &wire);
    }
}

#[test]
fn rtcp_reports_preserve_profile_extensions() {
    let registry = builtin::registry();
    let mut compound = Vec::new();
    for (kind, base_length) in [(200, 24), (201, 4)] {
        for count in [0, 1] {
            let body_length = base_length + 24 * usize::from(count) + 4;
            let mut wire = vec![0x80 | count, kind];
            wire.extend_from_slice(&((body_length / 4) as u16).to_be_bytes());
            wire.resize(4 + body_length - 4, 0);
            wire.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
            builder_round_trip("rtcp", &wire);
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
    builder_round_trip("rtcp", &compound);
}

#[test]
fn mqtt_persistent_sessions_require_a_client_identifier() {
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
            client_id: Bytes::copy_from_slice(client_id),
            ..Default::default()
        });
        assert_eq!(
            crate::build::Builder::new(registry.clone())
                .build(packet, Addresses::default(), Default::default())
                .is_ok(),
            valid
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
        assert_eq!(
            registry
                .codec("mqtt")
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

fn decode(name: &str, wire: &[u8]) -> Result<Decoded, crate::codec::Error> {
    let registry = builtin::registry();
    let decoded = registry.codec(name).unwrap().decode(
        Bytes::copy_from_slice(wire),
        &DecodeContext {
            parent: None,
            registry: &registry,
            network: None,
            hop_limit: None,
            discriminator: None,
        },
    )?;
    if decoded.layer.protocol_id().as_str() != name {
        return Err(crate::protocol::common::invalid(
            "test",
            "unsupported input retained raw",
        ));
    }
    Ok(decoded)
}

#[test]
fn text_targets_and_content_lengths() {
    for (name, version) in [("sip", "SIP/2.0"), ("rtsp", "RTSP/1.0")] {
        assert!(decode(name, format!("OPTIONS  {version}\r\n\r\n").as_bytes()).is_err());
        for length in ["0", " 0\t", "\t\r\n 0 "] {
            assert!(
                decode(
                    name,
                    format!("OPTIONS * {version}\r\nContent-Length:{length}\r\n\r\n").as_bytes()
                )
                .is_ok(),
                "{length:?}"
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
    for number in ["+1", "01", "-0", " 1"] {
        for tag in [":", "$", "*"] {
            let wire = format!("{tag}{number}\r\n");
            assert!(
                Framer::new("resp").progress(wire.as_bytes(), 4096).is_err(),
                "{wire:?}"
            );
            assert!(decode("resp", wire.as_bytes()).is_err());
        }
    }
    for leaf in [
        "+OK\r\n",
        ":0\r\n",
        "*0\r\n",
        "*-1\r\n",
        "$-1\r\n",
        "$0\r\n\r\n",
    ] {
        for depth in [15, 16] {
            let wire = format!("{}{leaf}", "*1\r\n".repeat(depth));
            let framed = Framer::new("resp").progress(wire.as_bytes(), 4096);
            assert_eq!(framed.is_ok(), depth == 15, "{leaf:?} at {depth}");
            assert_eq!(decode("resp", wire.as_bytes()).is_ok(), depth == 15);
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

#[test]
fn resp_null_reflection_requires_canonical_empty_data() {
    use crate::{field::Value, layer::ReflectiveField, protocol::application::resp::RespValue};
    for (kind, good, bad) in [
        (
            "null_bulk",
            Value::Bytes(Bytes::new()),
            Value::Bytes(Bytes::from_static(b"discarded")),
        ),
        (
            "null_array",
            Value::List(vec![]),
            Value::List(vec![Value::Unsigned(1)]),
        ),
    ] {
        let value = |data| {
            Value::Object(
                [
                    ("kind".into(), Value::Text(kind.into())),
                    ("data".into(), data),
                ]
                .into(),
            )
        };
        let mut resp = RespValue::Integer(1);
        resp.set_reflective_value(value(good)).unwrap();
        assert!(resp.set_reflective_value(value(bad)).is_err());
        assert!(
            resp.set_reflective_value(value(Value::Bool(false)))
                .is_err()
        );
    }
}

fn slice<'a>(name: &str, field: &str, wire: &'a [u8]) -> &'a [u8] {
    let decoded = decode(name, wire).unwrap();
    let range = decoded
        .fields
        .iter()
        .find(|f| f.name == field)
        .unwrap()
        .range;
    &wire[range.start..range.end]
}

#[test]
fn application_layouts_expose_exact_content_ranges() {
    for (name, version) in [("sip", "SIP/2.0"), ("rtsp", "RTSP/1.0")] {
        let wire = format!("OPTIONS * {version}\r\nContent-Length:3\r\n\r\nabc");
        assert_eq!(slice(name, "body", wire.as_bytes()), b"abc");
        let empty = format!("OPTIONS * {version}\r\nContent-Length:0\r\n\r\n");
        assert_eq!(slice(name, "body", empty.as_bytes()), b"");
    }
    assert_eq!(slice("rtsp", "body", b"$\x02\0\x03abc"), b"abc");
    let mut memcached = vec![0x80, 0, 0, 2, 1, 0, 0, 0, 0, 0, 0, 6];
    memcached.extend_from_slice(&[0; 12]);
    memcached.extend_from_slice(b"EKEval");
    for (field, expected) in [
        ("extras", b"E".as_slice()),
        ("key", b"KE"),
        ("value", b"val"),
    ] {
        assert_eq!(slice("memcached", field, &memcached), expected);
    }
    let ldap = b"\x30\x0a\x02\x01\x07\x65\x03\x0a\x01\0\xa0\0";
    for (field, expected) in [
        ("message_id", b"\x07".as_slice()),
        ("operation", b"\x65"),
        ("fields", b"\x0a\x01\0"),
        ("controls", b"\xa0\0"),
    ] {
        assert_eq!(slice("ldap", field, ldap), expected);
    }
    // Long-form lengths at both envelope and operation boundaries retain offsets.
    let mut operation = vec![4, 127];
    operation.extend([b'x'; 127]);
    let mut long_ldap = vec![0x30, 0x81, 137, 2, 1, 7, 0x65, 0x81, 129];
    long_ldap.extend_from_slice(&operation);
    long_ldap.extend_from_slice(&[0xa0, 0]);
    assert_eq!(slice("ldap", "message_id", &long_ldap), b"\x07");
    assert_eq!(slice("ldap", "fields", &long_ldap), operation);
    assert_eq!(slice("ldap", "controls", &long_ldap), b"\xa0\0");
    let coap = b"\x42\x01\0\x01TK\xb1x\x01y\xffPAY";
    for (field, expected) in [
        ("token", b"TK".as_slice()),
        ("options", b"\xb1x\x01y"),
        ("payload", b"PAY"),
    ] {
        assert_eq!(slice("coap", field, coap), expected);
    }
    for field in ["token", "options", "payload"] {
        assert_eq!(slice("coap", field, b"\x40\x01\0\x01"), b"");
    }
}

#[test]
fn mqtt_subscription_and_will_topics() {
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
            assert_eq!(decode("mqtt", &wire).is_ok(), valid, "{topic:?}");
        }
    }
    for topic in [b"will/topic".as_slice(), b"", b"will/+", b"will/#"] {
        let mut body = vec![0, 4, b'M', b'Q', b'T', b'T', 4, 6, 0, 60, 0, 0];
        sized(topic, &mut body);
        sized(b"payload", &mut body);
        let mut wire = vec![0x10, body.len() as u8];
        wire.extend(body);
        assert_eq!(decode("mqtt", &wire).is_ok(), topic == b"will/topic");
    }
}
