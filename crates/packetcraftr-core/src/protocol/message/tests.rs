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
    let mut packet = Packet::default();
    packet.push_boxed(decoded.layer);
    let addresses = network
        .map(|n| Addresses {
            source: Some(n.source),
            destination: Some(n.destination),
        })
        .unwrap_or_default();
    let context = EncodeContext {
        addresses: &addresses,
        mode: Mode::Strict,
        child: None,
        parent: None,
        network: network.ok_or_else(|| {
            crate::codec::Error::invalid(
                *packet.layer(0).unwrap().protocol_id(),
                "the transport checksum requires matching source and destination IP addresses",
            )
        }),
        outer_network: true,
        srh_active_segment: None,
        srh_reduced: false,
        under_ipv6: None,
        trailing_padding: Some(0),
        child_bindings: &[],
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
    let mut packet = Packet::default();
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
        crate::frame::Frame::new(None, crate::frame::LinkType::ETHERNET, built.bytes).unwrap();
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
fn coalesced_messages_preserve_tail() {
    let registry = builtin::registry();
    let mut packet = Packet::default();
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
    let frame =
        crate::frame::Frame::new(None, crate::frame::LinkType::ETHERNET, built.bytes.clone())
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
fn captures_rebuild_from_editable_documents() {
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
                    builder.replace_binding(
                        "udp",
                        port,
                        crate::protocol::BuiltinProtocol::from_name(child)
                            .unwrap()
                            .as_str(),
                        crate::registry::Priority::Primary,
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
        let mut reader =
            crate::capture_file::Reader::with_limits(&capture[..], Default::default()).unwrap();
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
fn ber_extensions_preserve_wire_bytes() {
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
fn malformed_resp_and_modbus_are_rejected() {
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
    let mut packet = Packet::default();
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
fn sip_without_length_uses_datagram() {
    let registry = builtin::registry();
    let mut packet = Packet::default();
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
            Frame::new(None, LinkType::ETHERNET, built.bytes.clone()).unwrap(),
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
fn udp_build_respects_registry_bindings() {
    let original = builtin::registry();
    let mut changed = original.to_builder();
    changed
        .replace_binding("udp", 5060, "coap", crate::registry::Priority::Primary)
        .unwrap();
    let changed = std::sync::Arc::new(changed.build().unwrap());
    let mut packet = Packet::default();
    packet.push(Ethernet::default());
    packet.push(Ipv4::default());
    packet.push(Udp {
        destination_port: 5060,
        ..Default::default()
    });
    packet.push(Sip::default());
    let original_builder = crate::build::Builder::new(original);
    let changed_builder = crate::build::Builder::new(changed);
    let bytes = original_builder
        .build(packet.clone(), Addresses::default(), Default::default())
        .unwrap()
        .bytes;
    assert!(
        changed_builder
            .build(packet.clone(), Addresses::default(), Default::default())
            .is_err()
    );
    assert_eq!(
        original_builder
            .build(packet, Addresses::default(), Default::default())
            .unwrap()
            .bytes,
        bytes
    );

    let mut malformed = Packet::default();
    malformed.push(Ethernet::default());
    malformed.push(Ipv4::default());
    malformed.push(Udp {
        destination_port: 5060,
        ..Default::default()
    });
    malformed.push(crate::layer::Malformed::new(
        Some("sip".to_owned()),
        Bytes::from_static(b"malformed SIP"),
        "invalid message",
    ));
    let permissive = crate::build::Options {
        mode: Mode::Permissive,
        ..Default::default()
    };
    let original_bytes = original_builder
        .build(malformed.clone(), Addresses::default(), permissive.clone())
        .unwrap()
        .bytes;
    let changed_bytes = changed_builder
        .build(malformed, Addresses::default(), permissive)
        .unwrap()
        .bytes;
    assert_eq!(changed_bytes, original_bytes);
}

#[test]
fn sip_tcp_still_requires_content_length() {
    let mut framer = crate::protocol::framing::Framer::new(crate::codec::Framing::Sip, "sip");
    assert!(
        framer
            .progress(b"OPTIONS sip:service SIP/2.0\r\n\r\n", 65536)
            .is_err()
    );
}

#[test]
fn ospfv2_preserves_authentication_digest() {
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
                parent: Some(crate::protocol::BuiltinProtocol::Ipv4.id()),
                registry: &registry,
                network: None,
                hop_limit: None,
                discriminator: None,
            },
        )
        .expect("authenticated OSPF is not a length error");
    assert_eq!(decoded.consumed, wire.len());
    let mut packet = Packet::default();
    packet.push_boxed(decoded.layer);
    let addresses = Addresses::default();
    let encoded = registry
        .codec(packet.layer(0).unwrap().protocol_id().as_str())
        .unwrap()
        .encode(
            packet.layer(0).unwrap(),
            &[],
            &EncodeContext {
                addresses: &addresses,
                mode: Mode::Strict,
                child: None,
                parent: None,
                network: Err(crate::codec::Error::invalid(
                    *packet.layer(0).unwrap().protocol_id(),
                    "the transport checksum requires matching source and destination IP addresses",
                )),
                outer_network: true,
                srh_active_segment: None,
                srh_reduced: false,
                under_ipv6: None,
                trailing_padding: Some(0),
                child_bindings: &[],
                remaining_packet_bytes: 65536,
            },
        )
        .unwrap();
    assert_eq!(encoded.prefix, wire);
}

#[test]
fn dtls_rejects_oversized_fragment_offsets() {
    let fragment = field::Value::Object(record([
        ("message_type", 1_u8.into()),
        ("length", 1_u8.into()),
        ("message_sequence", 0_u8.into()),
        ("offset", u64::MAX.into()),
        ("data", Bytes::from_static(b"x").into()),
    ]));
    let mut packet = Packet::default();
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
fn sflow_samples_support_edits_and_projection() {
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
            Frame::new(None, LinkType::ETHERNET, built.bytes).unwrap(),
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
fn strict_build_validates_sip_rtsp_framing() {
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
        let mut packet = Packet::default();
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
fn large_cdp_checksum_round_trips() {
    let mut packet = Packet::default();
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
    let mut packet = Packet::default();
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
                parent: Some(crate::protocol::BuiltinProtocol::Udp.id()),
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
    let mut packet = Packet::default();
    packet.push_boxed(decoded.layer);
    packet.push(crate::layer::Raw::new(Bytes::copy_from_slice(&wire[20..])));
    let built = crate::build::Builder::new(registry)
        .build(packet, Addresses::default(), Default::default())
        .unwrap();
    assert_eq!(built.bytes.as_ref(), wire);
}

#[test]
fn ethernet_ip_preserves_opaque_errors() {
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
fn ipfix_dtls_support_nested_field_edits() {
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
                    builder.replace_binding(
                        "udp",
                        5684,
                        "dtls",
                        crate::registry::Priority::Primary,
                    )?;
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
                Frame::new(None, LinkType::ETHERNET, built.bytes).unwrap(),
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
    let mut packet = Packet::default();
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
            Frame::new(None, LinkType::ETHERNET, built.bytes.clone()).unwrap(),
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
    let mut packet = Packet::default();
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
fn folded_sip_rtsp_headers_preserve_framing() {
    for (name, start) in [
        ("sip", "OPTIONS sip:service SIP/2.0"),
        ("rtsp", "OPTIONS * RTSP/1.0"),
    ] {
        let wire = format!("{start}\r\nSubject: a\r\n b\r\nContent-Length:\r\n\t4\r\n\r\nbody");
        builder_round_trip(name, wire.as_bytes());
        for split in 1..wire.len() {
            let mut framer = crate::protocol::framing::Framer::new(
                crate::protocol::BuiltinProtocol::from_name(name)
                    .unwrap()
                    .framing(),
                crate::protocol::BuiltinProtocol::from_name(name)
                    .unwrap()
                    .as_str(),
            );
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
    let mut packet = Packet::default();
    packet.push(sip);
    assert!(
        crate::build::Builder::new(builtin::registry())
            .build(packet, Addresses::default(), Default::default())
            .is_err()
    );
}

#[test]
fn amqp_requires_complete_property_flags() {
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
        let mut packet = Packet::default();
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
fn resp_supports_edits_filters_and_projection() {
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
        let mut packet = Packet::default();
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
                Frame::new(None, LinkType::ETHERNET, built.bytes).unwrap(),
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
fn bacnet_segment_ack_requires_window() {
    let ack = b"\x40\x01\x02\x01";
    for len in 0..=ack.len() {
        let registry = builtin::registry();
        let mut packet = Packet::default();
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
fn sip_preserves_trailing_datagram_bytes() {
    let registry = builtin::registry();
    let builder = crate::build::Builder::new(registry.clone());
    let mut packet = Packet::default();
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
            Frame::new(None, LinkType::ETHERNET, built.bytes.clone()).unwrap(),
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
fn ethernet_padding_preserves_datagram_framing() {
    let registry = builtin::registry();
    let builder = crate::build::Builder::new(registry.clone());
    for (network, port, application) in [
        ("ipv4", 5683, "coap()"),
        ("ipv4", 53, "dns()"),
        ("ipv6", 53, "dns()"),
        ("ipv4", 69, "tftp(opcode=4,block=1)"),
        ("ipv6", 69, "tftp(opcode=4,block=1)"),
        ("ipv4", 123, "ntp()"),
        ("ipv6", 123, "ntp()"),
        ("ipv4", 514, "syslog()"),
        ("ipv6", 514, "syslog()"),
        ("ipv4", 67, "dhcpv4()"),
        ("ipv6", 547, "dhcpv6()"),
    ] {
        let expression = format!("ethernet()/{network}()/udp(dport={port})/{application}");
        let packet = crate::expression::parse(&expression, &registry, Default::default()).unwrap();
        let protocol = application.split_once('(').unwrap().0;
        if protocol != "coap" {
            let mut with_child = packet.clone();
            with_child.push(crate::layer::Raw::new(Bytes::from_static(b"x")));
            with_child.push(crate::layer::Padding::after_layer(
                Bytes::from_static(b"pad"),
                1,
            ));
            let error = builder
                .build(
                    with_child,
                    Addresses::default(),
                    crate::build::Options {
                        mode: Mode::Permissive,
                        ..Default::default()
                    },
                )
                .unwrap_err();
            assert!(
                matches!(&error, crate::build::Error::Codec { protocol: refused, .. } if refused.as_str() == protocol),
                "{expression}: {error}"
            );
        }
        let mut padded = builder
            .build(packet, Addresses::default(), Default::default())
            .unwrap()
            .bytes
            .to_vec();
        padded.resize(padded.len().max(46) + 14, 0xa5);
        let decoded = crate::decode::Dissector::new(registry.clone())
            .decode(
                Frame::new(None, LinkType::ETHERNET, Bytes::copy_from_slice(&padded)).unwrap(),
                Default::default(),
            )
            .unwrap();
        assert_eq!(
            decoded.packet.layer(3).unwrap().protocol_id().as_str(),
            protocol,
            "{expression}"
        );
        assert_eq!(
            decoded
                .packet
                .get::<crate::layer::Padding>()
                .unwrap()
                .outside_layer,
            Some(1)
        );
        for mode in [Mode::Strict, Mode::Permissive] {
            let rebuilt = builder
                .build(
                    decoded.packet.clone(),
                    Addresses::default(),
                    crate::build::Options {
                        mode,
                        ..Default::default()
                    },
                )
                .unwrap_or_else(|error| panic!("{expression} ({mode:?}): {error}"));
            assert_eq!(rebuilt.bytes.as_ref(), padded, "{expression} ({mode:?})");
        }
    }
}

#[test]
fn interleaved_rtsp_exposes_binary_fields_only() {
    let registry = builtin::registry();
    let mut packet = Packet::default();
    packet.push(crate::protocol::application::rtsp::Rtsp {
        interleaved: true,
        channel: 7,
        body: Bytes::from_static(b"\r\n\r\n"),
        ..Default::default()
    });
    let built = crate::build::Builder::new(registry.clone())
        .build(packet, Addresses::default(), Default::default())
        .unwrap();
    let layer_layout = built.layout.layer(0).unwrap();
    let fields = &layer_layout.fields;
    assert_eq!(
        fields
            .iter()
            .map(|field| field.name(layer_layout.schema).unwrap())
            .collect::<Vec<_>>(),
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
fn non_lacp_slow_protocols_remain_opaque() {
    let registry = builtin::registry();
    for wire in [b"\x03\0\0\x01".as_slice(), b"\x02\x01", b"\x01\x02"] {
        let decoded = registry
            .codec("lacp")
            .unwrap()
            .decode(
                Bytes::copy_from_slice(wire),
                &DecodeContext {
                    parent: Some(crate::protocol::BuiltinProtocol::Ethernet.id()),
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
fn rtsp_sip_methods_accept_tokens() {
    for (name, version) in [("rtsp", "RTSP/1.0"), ("sip", "SIP/2.0")] {
        for method in ["GET_PARAMETER", "SET_PARAMETER", "custom_method2"] {
            let wire = format!("{method} * {version}\r\nContent-Length: 0\r\n\r\n");
            builder_round_trip(name, wire.as_bytes());
        }
    }
}

#[test]
fn rtcp_padding_preserves_report_boundaries() {
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
        let mut packet = Packet::default();
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
fn mqtt_persistent_sessions_require_client_id() {
    use crate::protocol::application::mqtt::Mqtt;
    let registry = builtin::registry();
    for (flags, client_id) in [
        (0, b"".as_slice()),
        (2, b""),
        (0, b"client"),
        (2, b"client"),
    ] {
        let valid = flags & 2 != 0 || !client_id.is_empty();
        let mut packet = Packet::default();
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
fn resp_framing_matches_decoder_depth() {
    for number in ["+1", "01", "-0", " 1"] {
        for tag in [":", "$", "*"] {
            let wire = format!("{tag}{number}\r\n");
            assert!(
                Framer::new(crate::codec::Framing::Resp, "resp")
                    .progress(wire.as_bytes(), 4096)
                    .is_err(),
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
            let framed =
                Framer::new(crate::codec::Framing::Resp, "resp").progress(wire.as_bytes(), 4096);
            assert_eq!(framed.is_ok(), depth == 15, "{leaf:?} at {depth}");
            assert_eq!(decode("resp", wire.as_bytes()).is_ok(), depth == 15);
        }
    }
    let wire = b"$9223372036854775807\r\n";
    assert!(
        Framer::new(crate::codec::Framing::Resp, "resp")
            .progress(wire, 4096)
            .is_err()
    );
    for wire in [b"$0\r\n\r\n".as_slice(), b"$3\r\nabc\r\n"] {
        assert_eq!(
            Framer::new(crate::codec::Framing::Resp, "resp")
                .progress(wire, 4096)
                .unwrap(),
            Some(wire.len())
        );
    }
}

#[test]
fn resp_null_requires_empty_data() {
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
        .find(|f| f.name(decoded.layer.schema()) == Some(field))
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

#[test]
fn layouts_stay_within_every_message_prefix() {
    use crate::protocol::{
        application::*,
        link::{CdpCodec, EapCodec, LacpCodec},
        network::{Ospfv2Codec, Ospfv3Codec, PimCodec, RipngCodec, Ripv2Codec},
        tunnel::{PppIpcpCodec, PppIpv6cpCodec, PppLcpCodec},
    };
    type Layout = fn(&[u8]) -> Vec<crate::layout::FieldLayout>;
    let layouts: [(&str, Layout); 36] = [
        ("amqp", AmqpCodec::layout),
        ("bacnet_ip", BacnetIpCodec::layout),
        ("bgp", BgpCodec::layout),
        ("cdp", CdpCodec::layout),
        ("coap", CoapCodec::layout),
        ("dnp3", Dnp3Codec::layout),
        ("dtls", DtlsCodec::layout),
        ("eap", EapCodec::layout),
        ("ethernet_ip", EthernetIpCodec::layout),
        ("iec104", Iec104Codec::layout),
        ("ipfix", IpfixCodec::layout),
        ("lacp", LacpCodec::layout),
        ("ldap", LdapCodec::layout),
        ("memcached", MemcachedCodec::layout),
        ("modbus_tcp", ModbusTcpCodec::layout),
        ("mqtt", MqttCodec::layout),
        ("netflowv5", Netflowv5Codec::layout),
        ("opcua_tcp", OpcuaTcpCodec::layout),
        ("ospfv2", Ospfv2Codec::layout),
        ("ospfv3", Ospfv3Codec::layout),
        ("pim", PimCodec::layout),
        ("ppp_ipcp", PppIpcpCodec::layout),
        ("ppp_ipv6cp", PppIpv6cpCodec::layout),
        ("ppp_lcp", PppLcpCodec::layout),
        ("radius", RadiusCodec::layout),
        ("resp", RespCodec::layout),
        ("ripng", RipngCodec::layout),
        ("ripv2", Ripv2Codec::layout),
        ("rtcp", RtcpCodec::layout),
        ("rtp", RtpCodec::layout),
        ("rtsp", RtspCodec::layout),
        ("sflow", SflowCodec::layout),
        ("sip", SipCodec::layout),
        ("snmp", SnmpCodec::layout),
        ("ssdp", SsdpCodec::layout),
        ("stun", StunCodec::layout),
    ];
    let manifest: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../../examples/captures/protocols.manifest.json"
    ))
    .unwrap();
    let rows = manifest["protocols"].as_array().unwrap();
    assert_eq!(rows.len(), layouts.len());
    let mut violations = std::collections::BTreeSet::new();
    for row in rows {
        let name = row["protocol"].as_str().unwrap();
        let (_, layout) = layouts
            .iter()
            .find(|(protocol, _)| *protocol == name)
            .unwrap_or_else(|| panic!("{name} has no layout under test"));
        let wire = crate::layer::parse_hex(row["wire_hex"].as_str().unwrap()).unwrap();
        assert_eq!(decode(name, &wire).unwrap().consumed, wire.len(), "{name}");
        for len in 0..=wire.len() {
            for field in layout(&wire[..len]) {
                if field.range.start > field.range.end || field.range.end > len {
                    violations.insert(format!("{name}.field{}", field.index));
                }
            }
        }
    }
    assert!(
        violations.is_empty(),
        "out-of-bounds layouts: {violations:?}"
    );
}

fn mqtt_over_tcp(messages: Vec<Box<dyn Layer>>) -> Packet {
    let mut packet = Packet::default();
    packet.push(Ethernet::default());
    packet.push(Ipv4::default());
    packet.push(Tcp {
        destination_port: 1883,
        ..Default::default()
    });
    for message in messages {
        packet.push_boxed(message);
    }
    packet
}

fn build_in(packet: Packet, mode: Mode) -> Result<crate::build::BuiltPacket, String> {
    crate::build::Builder::new(builtin::registry())
        .build(
            packet,
            Addresses::default(),
            crate::build::Options {
                mode,
                ..Default::default()
            },
        )
        .map_err(|error| match error {
            crate::build::Error::Codec { source, .. } => source.to_string(),
            other => other.to_string(),
        })
}

#[test]
fn mqtt_pingreq_rejects_payload() {
    let json = r#"{"schema":"packetcraftr.packet/v1","layers":[
        {"protocol":"ethernet","fields":{}},
        {"protocol":"ipv4","fields":{}},
        {"protocol":"tcp","fields":{"destination_port":{"type":"unsigned","value":1883}}},
        {"protocol":"mqtt","fields":{
            "packet_type":{"type":"unsigned","value":12},
            "payload":{"type":"bytes","value":[1,2,3]}}}]}"#;
    let document = document::Packet::parse(json, document::Format::Json, json.len()).unwrap();
    for mode in [Mode::Strict, Mode::Permissive] {
        let packet = document.to_packet(&builtin::registry(), 16).unwrap();
        let error = build_in(packet, mode).unwrap_err();
        assert!(
            error.ends_with("PINGREQ (packet type 12) does not carry field payload"),
            "{mode:?}: {error}"
        );
    }
}

#[test]
fn mqtt_rejects_fields_from_other_packets() {
    use crate::protocol::application::mqtt::Mqtt;
    let subscription = || {
        Records(vec![record([
            ("topic", Bytes::from_static(b"a/b").into()),
            ("qos", 1_u8.into()),
        ])])
    };
    for (mqtt, expected) in [
        (
            Mqtt {
                payload: Bytes::from_static(b"\x01\x02\x03"),
                ..Default::default()
            },
            "PINGREQ (packet type 12) does not carry field payload",
        ),
        (
            Mqtt {
                packet_type: 2,
                topic: Bytes::from_static(b"a"),
                ..Default::default()
            },
            "CONNACK (packet type 2) does not carry field topic",
        ),
        (
            Mqtt {
                packet_type: 3,
                topic: Bytes::from_static(b"a"),
                packet_id: 7,
                ..Default::default()
            },
            "PUBLISH (packet type 3) does not carry field packet_id",
        ),
        (
            Mqtt {
                packet_type: 1,
                client_id: Bytes::from_static(b"client"),
                will_topic: Bytes::from_static(b"will"),
                ..Default::default()
            },
            "CONNECT (packet type 1) does not carry field will_topic",
        ),
        (
            Mqtt {
                packet_type: 1,
                connect_flags: 0x82,
                user_name: Bytes::from_static(b"user"),
                password: Bytes::from_static(b"secret"),
                ..Default::default()
            },
            "CONNECT (packet type 1) does not carry field password",
        ),
        (
            Mqtt {
                packet_type: 9,
                payload: Bytes::from_static(b"\x00"),
                subscriptions: subscription(),
                ..Default::default()
            },
            "SUBACK (packet type 9) does not carry field subscriptions",
        ),
        (
            Mqtt {
                packet_type: 10,
                flags: 2,
                subscriptions: subscription(),
                ..Default::default()
            },
            "UNSUBSCRIBE (packet type 10) does not carry field subscriptions[0].qos",
        ),
        (
            Mqtt {
                packet_type: 14,
                keep_alive: 30,
                ..Default::default()
            },
            "DISCONNECT (packet type 14) does not carry field keep_alive",
        ),
        (
            Mqtt {
                packet_type: 13,
                connect_flags: 0,
                ..Default::default()
            },
            "PINGRESP (packet type 13) does not carry field connect_flags",
        ),
        (
            Mqtt {
                packet_type: 4,
                client_id: Bytes::from_static(b"client"),
                ..Default::default()
            },
            "PUBACK (packet type 4) does not carry field client_id",
        ),
        (
            Mqtt {
                packet_type: 1,
                client_id: Bytes::from_static(b"client"),
                will_payload: Bytes::from_static(b"will"),
                ..Default::default()
            },
            "CONNECT (packet type 1) does not carry field will_payload",
        ),
        (
            Mqtt {
                packet_type: 1,
                user_name: Bytes::from_static(b"user"),
                ..Default::default()
            },
            "CONNECT (packet type 1) does not carry field user_name",
        ),
        (
            Mqtt {
                packet_type: 5,
                session_present: 1,
                ..Default::default()
            },
            "PUBREC (packet type 5) does not carry field session_present",
        ),
        (
            Mqtt {
                packet_type: 11,
                return_code: 1,
                ..Default::default()
            },
            "UNSUBACK (packet type 11) does not carry field return_code",
        ),
    ] {
        for mode in [Mode::Strict, Mode::Permissive] {
            let error = build_in(mqtt_over_tcp(vec![Box::new(mqtt.clone())]), mode).unwrap_err();
            assert!(error.ends_with(expected), "{mode:?}: {error}");
        }
    }
}

#[test]
fn mqtt_fields_round_trip() {
    use crate::protocol::application::mqtt::Mqtt;
    let registry = builtin::registry();
    for mqtt in [
        Mqtt::default(),
        Mqtt {
            packet_type: 1,
            client_id: Bytes::from_static(b"client"),
            keep_alive: 30,
            ..Default::default()
        },
        Mqtt {
            packet_type: 1,
            connect_flags: 0xee,
            client_id: Bytes::from_static(b"client"),
            will_topic: Bytes::from_static(b"will/topic"),
            will_payload: Bytes::from_static(b"gone"),
            user_name: Bytes::from_static(b"user"),
            password: Bytes::from_static(b"secret"),
            ..Default::default()
        },
        Mqtt {
            packet_type: 3,
            topic: Bytes::from_static(b"a/b"),
            payload: Bytes::from_static(b"data"),
            ..Default::default()
        },
        Mqtt {
            packet_type: 3,
            flags: 2,
            topic: Bytes::from_static(b"a/b"),
            packet_id: 7,
            payload: Bytes::from_static(b"data"),
            ..Default::default()
        },
        Mqtt {
            packet_type: 2,
            session_present: 1,
            ..Default::default()
        },
        Mqtt {
            packet_type: 2,
            return_code: 5,
            ..Default::default()
        },
        Mqtt {
            packet_type: 9,
            packet_id: 7,
            payload: Bytes::from_static(b"\x01\x80"),
            ..Default::default()
        },
        Mqtt {
            packet_type: 10,
            flags: 2,
            packet_id: 7,
            subscriptions: Records(vec![record([("topic", Bytes::from_static(b"a/#").into())])]),
            ..Default::default()
        },
        Mqtt {
            packet_type: 8,
            flags: 2,
            packet_id: 7,
            subscriptions: Records(vec![record([
                ("topic", Bytes::from_static(b"a/+").into()),
                ("qos", 1_u8.into()),
            ])]),
            ..Default::default()
        },
    ] {
        let built = build_in(mqtt_over_tcp(vec![Box::new(mqtt.clone())]), Mode::Strict).unwrap();
        let decoded = crate::decode::Dissector::new(registry.clone())
            .decode(
                Frame::new(None, LinkType::ETHERNET, built.bytes.clone()).unwrap(),
                Default::default(),
            )
            .unwrap();
        assert_eq!(decoded.packet.get::<Mqtt>(), Some(&mqtt));
        let json = serde_json::to_string(&document::Packet::from_packet(&decoded.packet)).unwrap();
        let document = document::Packet::parse(&json, document::Format::Json, json.len()).unwrap();
        let rebuilt = build_in(document.to_packet(&registry, 16).unwrap(), Mode::Strict).unwrap();
        assert_eq!(rebuilt.bytes, built.bytes, "{mqtt:?}");
    }
}

#[test]
fn permissive_mqtt_preserves_malformed_messages() {
    use crate::protocol::application::mqtt::Mqtt;
    let persistent_without_client = Mqtt {
        packet_type: 1,
        connect_flags: 0,
        ..Default::default()
    };
    let packet = mqtt_over_tcp(vec![Box::new(persistent_without_client.clone())]);
    let error = build_in(packet.clone(), Mode::Strict).unwrap_err();
    assert!(error.contains("client identifier"), "{error}");
    let built = build_in(packet, Mode::Permissive).unwrap();
    assert!(built.diagnostics.iter().any(|d| d.code == "build.message"));
    assert_eq!(built.packet.get::<Mqtt>(), Some(&persistent_without_client));
    assert!(built.bytes.ends_with(b"\x10\x0c\0\x04MQTT\x04\0\0\x3c\0\0"));

    let built = build_in(
        mqtt_over_tcp(vec![
            Box::new(Mqtt::default()),
            Box::new(crate::layer::Raw::new(Bytes::from_static(b"\x01\x02\x03"))),
        ]),
        Mode::Strict,
    )
    .unwrap();
    assert!(built.bytes.ends_with(b"\xc0\0\x01\x02\x03"));
}

#[test]
fn strict_validation_errors_and_permissive_warns() {
    use crate::protocol::application::{coap::Coap, mqtt::Mqtt, rtsp::Rtsp, ssdp::Ssdp};
    let udp = |port| -> Box<dyn Layer> {
        Box::new(Udp {
            destination_port: port,
            ..Default::default()
        })
    };
    let tcp = |port| -> Box<dyn Layer> {
        Box::new(Tcp {
            destination_port: port,
            ..Default::default()
        })
    };
    let cases: [([Box<dyn Layer>; 3], &str); 5] = [
        (
            [
                udp(5683),
                Box::new(Coap::default()),
                Box::new(Coap {
                    code: 0,
                    token: Bytes::from_static(b"t"),
                    ..Default::default()
                }),
            ],
            "empty CoAP message contains data",
        ),
        (
            [
                udp(5060),
                Box::new(Sip::default()),
                Box::new(Sip {
                    start_line: Bytes::from_static(b"OPTIONS sip:service SIP/3.0"),
                    ..Default::default()
                }),
            ],
            "unsupported start line or version",
        ),
        (
            [
                udp(1900),
                Box::new(Ssdp::default()),
                Box::new(Ssdp {
                    start_line: Bytes::from_static(b"SUBSCRIBE * HTTP/1.1"),
                    ..Default::default()
                }),
            ],
            "unknown SSDP start line",
        ),
        (
            [
                tcp(554),
                Box::new(Rtsp::default()),
                Box::new(Rtsp {
                    start_line: Bytes::from_static(b"OPTIONS * HTTP/1.1"),
                    ..Default::default()
                }),
            ],
            "unsupported start line or version",
        ),
        (
            [
                tcp(1883),
                Box::new(Mqtt::default()),
                Box::new(Mqtt {
                    packet_type: 2,
                    return_code: 6,
                    ..Default::default()
                }),
            ],
            "invalid CONNACK",
        ),
    ];
    let fields = |layer: &dyn Layer| {
        layer
            .schema()
            .fields
            .iter()
            .map(|field| layer.field(field.name))
            .collect::<Vec<_>>()
    };
    let registry = builtin::registry();
    let mut refused = Vec::new();
    for ([transport, valid, invalid], expected) in cases {
        let stack = |message: Box<dyn Layer>| {
            let mut packet = Packet::default();
            packet.push(Ethernet::default());
            packet.push(Ipv4::default());
            packet.push_boxed(transport.clone_box());
            packet.push_boxed(message);
            packet
        };
        let name = valid.protocol_id().as_str().to_owned();
        let built = build_in(stack(valid.clone_box()), Mode::Strict).unwrap();
        assert!(
            built.diagnostics.is_empty(),
            "{name}: {:?}",
            built.diagnostics
        );
        let decoded = crate::decode::Dissector::new(registry.clone())
            .decode(
                Frame::new(None, LinkType::ETHERNET, built.bytes).unwrap(),
                Default::default(),
            )
            .unwrap();
        assert_eq!(
            decoded.packet.layer(3).map(fields),
            Some(fields(valid.as_ref())),
            "{name}"
        );

        let error = build_in(stack(invalid.clone_box()), Mode::Strict).unwrap_err();
        assert!(error.contains(expected), "{name}: {error}");
        let built = match build_in(stack(invalid.clone_box()), Mode::Permissive) {
            Ok(built) => built,
            Err(error) => {
                refused.push(format!("{name}: {error}"));
                continue;
            }
        };
        assert!(
            built
                .diagnostics
                .iter()
                .any(|d| d.code == "build.message" && d.message.contains(expected)),
            "{name}: {:?}",
            built.diagnostics
        );
        assert_eq!(
            built.packet.layer(3).map(fields),
            Some(fields(invalid.as_ref())),
            "{name}"
        );
    }
    assert!(refused.is_empty(), "permissive builds refused: {refused:?}");
}

fn rtsp_over_tcp(rtsp: crate::protocol::application::rtsp::Rtsp) -> Packet {
    let mut packet = Packet::default();
    packet.push(Ethernet::default());
    packet.push(Ipv4::default());
    packet.push(Tcp {
        destination_port: 554,
        ..Default::default()
    });
    packet.push(rtsp);
    packet
}

#[test]
fn rtsp_rejects_fields_from_other_framings() {
    use crate::protocol::application::rtsp::Rtsp;
    let interleaved = || Rtsp {
        interleaved: true,
        channel: 7,
        body: Bytes::from_static(b"\r\n\r\n"),
        ..Default::default()
    };
    for (rtsp, expected) in [
        (
            Rtsp {
                start_line: Bytes::from_static(b"DESCRIBE * RTSP/1.0"),
                ..interleaved()
            },
            "interleaved RTSP frames do not carry field start_line",
        ),
        (
            Rtsp {
                headers: Records::default(),
                ..interleaved()
            },
            "interleaved RTSP frames do not carry field headers",
        ),
        (
            Rtsp {
                channel: 3,
                ..Default::default()
            },
            "text RTSP messages do not carry field channel",
        ),
    ] {
        for mode in [Mode::Strict, Mode::Permissive] {
            let error = build_in(rtsp_over_tcp(rtsp.clone()), mode).unwrap_err();
            assert!(error.ends_with(expected), "{mode:?}: {error}");
        }
    }
    let json = r#"{"schema":"packetcraftr.packet/v1","layers":[
        {"protocol":"ethernet","fields":{}},
        {"protocol":"ipv4","fields":{}},
        {"protocol":"tcp","fields":{"destination_port":{"type":"unsigned","value":554}}},
        {"protocol":"rtsp","fields":{
            "interleaved":{"type":"bool","value":true},
            "start_line":{"type":"bytes","value":[68,69,83,67,82,73,66,69]},
            "body":{"type":"bytes","value":[1,2]}}}]}"#;
    let document = document::Packet::parse(json, document::Format::Json, json.len()).unwrap();
    for mode in [Mode::Strict, Mode::Permissive] {
        let packet = document.to_packet(&builtin::registry(), 16).unwrap();
        let error = build_in(packet, mode).unwrap_err();
        assert!(
            error.ends_with("interleaved RTSP frames do not carry field start_line"),
            "{mode:?}: {error}"
        );
    }
}

#[test]
fn rtsp_text_and_binary_round_trip() {
    use crate::protocol::application::rtsp::Rtsp;
    let registry = builtin::registry();
    let json = include_str!("../../../../../examples/documents/packet-rtsp.json");
    let text = document::Packet::parse(json, document::Format::Json, json.len())
        .unwrap()
        .to_packet(&registry, 16)
        .unwrap();
    let interleaved = rtsp_over_tcp(Rtsp {
        interleaved: true,
        channel: 7,
        body: Bytes::from_static(b"\r\n\r\n"),
        ..Default::default()
    });
    for packet in [text, interleaved] {
        let expected = packet.get::<Rtsp>().unwrap().clone();
        let built = build_in(packet, Mode::Strict).unwrap();
        let decoded = crate::decode::Dissector::new(registry.clone())
            .decode(
                Frame::new(None, LinkType::ETHERNET, built.bytes.clone()).unwrap(),
                Default::default(),
            )
            .unwrap();
        assert_eq!(decoded.packet.get::<Rtsp>(), Some(&expected));
        let json = serde_json::to_string(&document::Packet::from_packet(&decoded.packet)).unwrap();
        let document = document::Packet::parse(&json, document::Format::Json, json.len()).unwrap();
        let rebuilt = build_in(document.to_packet(&registry, 16).unwrap(), Mode::Strict).unwrap();
        assert_eq!(rebuilt.bytes, built.bytes, "{expected:?}");
    }
}
