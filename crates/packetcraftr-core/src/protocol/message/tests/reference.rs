// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
use super::*;

#[test]
fn application_reference_vectors() {
    // https://docs.oasis-open.org/mqtt/mqtt/v3.1.1/os/mqtt-v3.1.1-os.html checked 2026-10-25.
    round_trip(
        "mqtt",
        &[0x30, 4, 0, 1, b'a', b'x'],
        &[
            ("packet_type", 3_u8.into()),
            ("topic", Bytes::from_static(b"a").into()),
            ("payload", Bytes::from_static(b"x").into()),
        ],
    );
    // https://docs.oasis-open.org/mqtt/mqtt/v3.1.1/os/mqtt-v3.1.1-os.html checked 2026-10-25.
    round_trip(
        "mqtt",
        &[0x10, 12, 0, 4, b'M', b'Q', b'T', b'T', 4, 2, 0, 60, 0, 0],
        &[
            ("packet_type", 1_u8.into()),
            ("connect_flags", 2_u8.into()),
            ("keep_alive", 60_u16.into()),
            ("client_id", Bytes::new().into()),
        ],
    );
    // https://datatracker.ietf.org/doc/html/rfc7252#section-3 checked 2026-10-25.
    round_trip(
        "coap",
        &[0x40, 1, 0x12, 0x34],
        &[
            ("version", 1_u8.into()),
            ("code", 1_u8.into()),
            ("message_id", 0x1234_u16.into()),
        ],
    );
    // https://www.rabbitmq.com/resources/specs/amqp0-9-1.pdf checked 2026-10-25.
    round_trip(
        "amqp",
        &[8, 0, 0, 0, 0, 0, 0, 0xce],
        &[
            ("frame_type", 8_u8.into()),
            ("channel", 0_u16.into()),
            ("payload", Bytes::new().into()),
        ],
    );
    // https://www.rabbitmq.com/resources/specs/amqp0-9-1.pdf checked 2026-10-25.
    round_trip("amqp", b"AMQP\0\0\x09\x01", &[("frame_type", 0_u8.into())]);
    // https://redis.io/docs/latest/reference/protocol-spec/ checked 2026-10-25.
    round_trip(
        "resp",
        b"*2\r\n$3\r\nGET\r\n$1\r\nx\r\n",
        &[
            ("value.kind", "array".into()),
            ("value.data[0].kind", "bulk".into()),
            ("value.data[0].data", Bytes::from_static(b"GET").into()),
            ("value.data[1].data", Bytes::from_static(b"x").into()),
        ],
    );
    // https://docs.memcached.org/protocols/binary/ checked 2026-10-25.
    round_trip(
        "memcached",
        &[
            0x80, 10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ],
        &[
            ("magic", 0x80_u8.into()),
            ("opcode", 10_u8.into()),
            ("key", Bytes::new().into()),
            ("value", Bytes::new().into()),
        ],
    );
    // https://openconnectivity.org/upnp-specs/UPnP-arch-DeviceArchitecture-v2.0-20200417.pdf checked 2026-10-25.
    round_trip(
        "ssdp",
        b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n\r\n",
        &[
            (
                "start_line",
                Bytes::from_static(b"M-SEARCH * HTTP/1.1").into(),
            ),
            ("headers[0].name", Bytes::from_static(b"HOST").into()),
            (
                "headers[0].value",
                Bytes::from_static(b" 239.255.255.250:1900").into(),
            ),
        ],
    );
}

#[test]
fn protocol_expansion_reference_vectors() {
    let manifest: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../../../examples/captures/protocols.manifest.json"
    ))
    .unwrap();
    let cases: &[(&str, &[(&str, field::Value)])] = &[
        // https://docs.oasis-open.org/mqtt/mqtt/v3.1.1/os/mqtt-v3.1.1-os.html checked 2026-10-25.
        (
            "mqtt",
            &[
                ("packet_type", 3_u8.into()),
                ("topic", Bytes::from_static(b"a").into()),
                ("payload", Bytes::from_static(b"x").into()),
            ],
        ),
        // https://datatracker.ietf.org/doc/html/rfc7252#section-3 checked 2026-10-25.
        (
            "coap",
            &[
                ("version", 1_u8.into()),
                ("code", 1_u8.into()),
                ("message_id", 0x1234_u16.into()),
                ("options[0].number", 11_u16.into()),
                ("options[0].value", Bytes::from_static(b"test").into()),
            ],
        ),
        // https://www.rabbitmq.com/resources/specs/amqp0-9-1.pdf checked 2026-10-25.
        (
            "amqp",
            &[
                ("frame_type", 8_u8.into()),
                ("channel", 0_u16.into()),
                ("payload", Bytes::new().into()),
            ],
        ),
        // https://redis.io/docs/latest/reference/protocol-spec/ checked 2026-10-25.
        (
            "resp",
            &[
                ("value.kind", "array".into()),
                ("value.data[0].kind", "bulk".into()),
                ("value.data[0].data", Bytes::from_static(b"GET").into()),
                ("value.data[1].data", Bytes::from_static(b"x").into()),
            ],
        ),
        // https://docs.memcached.org/protocols/binary/ checked 2026-10-25.
        (
            "memcached",
            &[
                ("magic", 0x80_u8.into()),
                ("opcode", 10_u8.into()),
                ("key", Bytes::new().into()),
                ("value", Bytes::new().into()),
            ],
        ),
        // https://openconnectivity.org/upnp-specs/UPnP-arch-DeviceArchitecture-v2.0-20200417.pdf checked 2026-10-25.
        (
            "ssdp",
            &[
                (
                    "start_line",
                    Bytes::from_static(b"M-SEARCH * HTTP/1.1").into(),
                ),
                ("headers[0].name", Bytes::from_static(b"HOST").into()),
                (
                    "headers[0].value",
                    Bytes::from_static(b" 239.255.255.250:1900").into(),
                ),
            ],
        ),
        // https://datatracker.ietf.org/doc/html/rfc3748#section-4 checked 2026-10-25.
        (
            "eap",
            &[
                ("code", 1_u8.into()),
                ("identifier", 1_u8.into()),
                ("method", 1_u8.into()),
                ("data", Bytes::from_static(b"alice").into()),
            ],
        ),
        // https://raw.githubusercontent.com/DPDK/dpdk/main/drivers/net/bonding/rte_eth_bond_8023ad.h checked 2026-10-25.
        (
            "lacp",
            &[
                ("actor_system", field::Value::Mac([2, 0, 0, 0, 0, 1])),
                ("partner_system", field::Value::Mac([2, 0, 0, 0, 0, 2])),
                ("actor_port", 1_u16.into()),
                ("partner_port", 2_u16.into()),
                ("actor_state", 63_u8.into()),
            ],
        ),
        // https://raw.githubusercontent.com/wireshark/wireshark/master/epan/dissectors/packet-cdp.c checked 2026-10-25.
        (
            "cdp",
            &[
                ("version", 2_u8.into()),
                ("ttl", 180_u8.into()),
                ("tlvs[0].kind", 1_u16.into()),
                ("tlvs[0].value", Bytes::from_static(b"switch").into()),
            ],
        ),
        // https://datatracker.ietf.org/doc/html/rfc1661#section-6.1 checked 2026-10-25.
        (
            "ppp_lcp",
            &[
                ("code", 1_u8.into()),
                ("identifier", 1_u8.into()),
                ("options[0].kind", 1_u8.into()),
                ("options[0].value", Bytes::from_static(b"\x05\xdc").into()),
            ],
        ),
        // https://datatracker.ietf.org/doc/html/rfc1332#section-3.3 checked 2026-10-25.
        (
            "ppp_ipcp",
            &[
                ("code", 1_u8.into()),
                ("identifier", 1_u8.into()),
                ("options[0].kind", 3_u8.into()),
                (
                    "options[0].value",
                    Bytes::from_static(b"\xc0\0\x02\x01").into(),
                ),
            ],
        ),
        // https://datatracker.ietf.org/doc/html/rfc5072#section-4.1 checked 2026-10-25.
        (
            "ppp_ipv6cp",
            &[
                ("code", 1_u8.into()),
                ("identifier", 1_u8.into()),
                ("options[0].kind", 1_u8.into()),
                (
                    "options[0].value",
                    Bytes::from_static(b"\x02\0\0\0\0\0\0\x01").into(),
                ),
            ],
        ),
        // https://datatracker.ietf.org/doc/html/rfc4271#section-4.2 checked 2026-10-25.
        (
            "bgp",
            &[
                ("message_type", 1_u8.into()),
                ("version", 4_u8.into()),
                ("my_as", 64512_u16.into()),
                ("hold_time", 90_u16.into()),
                (
                    "identifier",
                    field::Value::Ipv4("192.0.2.1".parse().unwrap()),
                ),
            ],
        ),
        // https://datatracker.ietf.org/doc/html/rfc2328#appendix-A.3 checked 2026-10-25.
        (
            "ospfv2",
            &[
                ("packet_type", 1_u8.into()),
                ("router_id", 0xc0000201_u32.into()),
                ("network_mask", 0xffffff00_u32.into()),
                ("hello_interval", 10_u16.into()),
                ("dead_interval", 40_u32.into()),
            ],
        ),
        // https://datatracker.ietf.org/doc/html/rfc5340#appendix-A.3.2 checked 2026-10-25.
        (
            "ospfv3",
            &[
                ("packet_type", 1_u8.into()),
                ("router_id", 0xc0000201_u32.into()),
                ("interface_id", 1_u32.into()),
                ("options", 19_u32.into()),
                ("hello_interval", 10_u16.into()),
                ("dead_interval", 40_u32.into()),
            ],
        ),
        // https://datatracker.ietf.org/doc/html/rfc2453#section-3.6 checked 2026-10-25.
        (
            "ripv2",
            &[
                ("command", 2_u8.into()),
                (
                    "routes[0].address",
                    field::Value::Ipv4("198.51.100.0".parse().unwrap()),
                ),
                (
                    "routes[0].mask",
                    field::Value::Ipv4("255.255.255.0".parse().unwrap()),
                ),
                ("routes[0].metric", 2_u32.into()),
            ],
        ),
        // https://datatracker.ietf.org/doc/html/rfc2080#section-2.1 checked 2026-10-25.
        (
            "ripng",
            &[
                ("command", 2_u8.into()),
                (
                    "routes[0].prefix",
                    field::Value::Ipv6("2001:db8:1::".parse().unwrap()),
                ),
                ("routes[0].length", 64_u8.into()),
                ("routes[0].metric", 2_u8.into()),
            ],
        ),
        // https://datatracker.ietf.org/doc/html/rfc7761#section-4.9 checked 2026-10-25.
        (
            "pim",
            &[
                ("message_type", 0_u8.into()),
                ("options[0].kind", 1_u16.into()),
                ("options[0].value", Bytes::from_static(b"\0\x69").into()),
            ],
        ),
        // https://datatracker.ietf.org/doc/html/rfc3416#section-3 checked 2026-10-25.
        (
            "snmp",
            &[
                ("version", 1_u8.into()),
                ("community", Bytes::from_static(b"public").into()),
                ("pdu_type", 0xa0_u8.into()),
                ("request_id", field::Value::Signed(1)),
                (
                    "varbinds[0].oid",
                    Bytes::from_static(b"\x2b\x06\x01\x02\x01\x01\x01\0").into(),
                ),
                ("varbinds[0].tag", 5_u8.into()),
            ],
        ),
        // https://datatracker.ietf.org/doc/html/rfc2865#section-3 checked 2026-10-25.
        (
            "radius",
            &[
                ("code", 1_u8.into()),
                ("identifier", 7_u8.into()),
                ("attributes[0].kind", 1_u8.into()),
                ("attributes[0].value", Bytes::from_static(b"alice").into()),
            ],
        ),
        // https://datatracker.ietf.org/doc/html/rfc4511#section-4.1.1 checked 2026-10-25.
        (
            "ldap",
            &[
                ("message_id", 1_u8.into()),
                ("operation", 0x60_u8.into()),
                ("fields[0].tag", 2_u8.into()),
                ("fields[0].value", Bytes::from_static(b"\x03").into()),
                ("fields[2].tag", 0x80_u8.into()),
            ],
        ),
        // https://raw.githubusercontent.com/wireshark/wireshark/master/epan/dissectors/packet-netflow.c checked 2026-10-25.
        (
            "netflowv5",
            &[
                ("uptime", 1000_u32.into()),
                ("sequence", 1_u32.into()),
                (
                    "records[0].source",
                    field::Value::Ipv4("192.0.2.1".parse().unwrap()),
                ),
                (
                    "records[0].destination",
                    field::Value::Ipv4("198.51.100.1".parse().unwrap()),
                ),
                ("records[0].packets", 10_u32.into()),
                ("records[0].octets", 800_u32.into()),
                ("records[0].destination_port", 443_u16.into()),
            ],
        ),
        // https://datatracker.ietf.org/doc/html/rfc7011#section-3 checked 2026-10-25.
        (
            "ipfix",
            &[
                ("observation_domain", 1_u32.into()),
                ("sets[0].id", 2_u16.into()),
                ("sets[0].records[0].template_id", 256_u16.into()),
                ("sets[0].records[0].fields[0].element_id", 8_u16.into()),
                ("sets[0].records[0].fields[0].length", 4_u16.into()),
                ("sets[1].data", Bytes::from_static(b"\xc0\0\x02\x01").into()),
            ],
        ),
        // https://sflow.org/sflow_version_5.txt checked 2026-10-25.
        (
            "sflow",
            &[
                (
                    "agent_address",
                    Bytes::from_static(b"\xc0\0\x02\x01").into(),
                ),
                ("sequence", 1_u32.into()),
                ("samples[0].sampling_rate", 100_u32.into()),
                ("samples[0].input", 1_u32.into()),
                ("samples[0].output", 2_u32.into()),
            ],
        ),
        // https://datatracker.ietf.org/doc/html/rfc3261#section-7 checked 2026-10-25.
        (
            "sip",
            &[
                (
                    "start_line",
                    Bytes::from_static(b"OPTIONS sip:service SIP/2.0").into(),
                ),
                ("headers[0].name", Bytes::from_static(b"CSeq").into()),
                ("headers[0].value", Bytes::from_static(b" 1 OPTIONS").into()),
                ("body", Bytes::new().into()),
            ],
        ),
        // https://datatracker.ietf.org/doc/html/rfc2326#section-4 checked 2026-10-25.
        (
            "rtsp",
            &[
                (
                    "start_line",
                    Bytes::from_static(b"OPTIONS * RTSP/1.0").into(),
                ),
                ("headers[0].name", Bytes::from_static(b"CSeq").into()),
                ("headers[0].value", Bytes::from_static(b" 1").into()),
                ("body", Bytes::new().into()),
            ],
        ),
        // https://datatracker.ietf.org/doc/html/rfc3550#section-5.1 checked 2026-10-25.
        (
            "rtp",
            &[
                ("payload_type", 96_u8.into()),
                ("sequence", 1_u16.into()),
                ("timestamp", 1_u32.into()),
                ("ssrc", 1_u32.into()),
                ("payload", Bytes::from_static(b"\0\x01").into()),
            ],
        ),
        // https://datatracker.ietf.org/doc/html/rfc3550#section-6.4 checked 2026-10-25.
        (
            "rtcp",
            &[
                ("packets[0].packet_type", 200_u8.into()),
                ("packets[0].count", 0_u8.into()),
                (
                    "packets[0].data",
                    Bytes::from_static(b"\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0")
                        .into(),
                ),
            ],
        ),
        // https://datatracker.ietf.org/doc/html/rfc8489#section-5 checked 2026-10-25.
        (
            "stun",
            &[
                ("message_type", 0x101_u16.into()),
                ("transaction_id", Bytes::from_static(&[1; 12]).into()),
                ("attributes[0].kind", 0x20_u16.into()),
                (
                    "attributes[0].value",
                    Bytes::from_static(b"\0\x01\xf5\x23\xe1\x12\xa6\x43").into(),
                ),
            ],
        ),
        // https://datatracker.ietf.org/doc/html/rfc6347#section-4.2.2 checked 2026-10-25.
        (
            "dtls",
            &[
                ("records[0].content_type", 22_u8.into()),
                ("records[0].handshakes[0].message_type", 14_u8.into()),
                ("records[0].handshakes[0].length", 0_u32.into()),
                ("records[0].handshakes[0].data", Bytes::new().into()),
            ],
        ),
        // https://www.modbus.org/file/secure/modbusprotocolspecification.pdf checked 2026-10-25.
        (
            "modbus_tcp",
            &[
                ("transaction_id", 1_u16.into()),
                ("unit_id", 1_u8.into()),
                ("function", 3_u8.into()),
                ("data", Bytes::from_static(b"\0\0\0\x02").into()),
            ],
        ),
        // https://raw.githubusercontent.com/wireshark/wireshark/master/epan/dissectors/packet-bvlc.c checked 2026-10-25.
        (
            "bacnet_ip",
            &[
                ("bvlc_function", 10_u8.into()),
                ("control", 0_u8.into()),
                ("data", Bytes::from_static(b"\x10\x08").into()),
            ],
        ),
        // https://raw.githubusercontent.com/wireshark/wireshark/master/epan/dissectors/packet-dnp.c checked 2026-10-25.
        (
            "dnp3",
            &[
                ("control", 0xc0_u8.into()),
                ("destination", 1_u16.into()),
                ("source", 1024_u16.into()),
                ("has_transport", false.into()),
            ],
        ),
        // https://raw.githubusercontent.com/wireshark/wireshark/master/epan/dissectors/packet-enip.c checked 2026-10-25.
        (
            "ethernet_ip",
            &[
                ("command", 0x65_u16.into()),
                ("session", 0_u32.into()),
                ("protocol_version", 1_u16.into()),
                ("flags", 0_u16.into()),
            ],
        ),
        // https://raw.githubusercontent.com/wireshark/wireshark/master/epan/dissectors/packet-iec104.c checked 2026-10-25.
        (
            "iec104",
            &[("frame_type", "u".into()), ("u_control", 7_u8.into())],
        ),
        // https://reference.opcfoundation.org/specs/OPC-10000-6/7.1.2.3 checked 2026-10-25.
        (
            "opcua_tcp",
            &[
                ("message_type", Bytes::from_static(b"HEL").into()),
                ("chunk_type", b'F'.into()),
                ("receive_buffer", 8192_u32.into()),
                ("send_buffer", 8192_u32.into()),
                (
                    "endpoint_url",
                    Bytes::from_static(b"opc.tcp://localhost:4840").into(),
                ),
            ],
        ),
    ];
    for (name, expected) in cases {
        let vector = manifest["protocols"]
            .as_array()
            .unwrap()
            .iter()
            .find(|row| row["protocol"] == *name)
            .unwrap();
        let wire = crate::layer::parse_hex(vector["wire_hex"].as_str().unwrap()).unwrap();
        if *name == "ospfv3" {
            round_trip_ipv6(name, &wire, expected);
            continue;
        }
        round_trip(name, &wire, expected);
    }
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
    packet.push(crate::protocol::network::ospfv3::Ospfv3 {
        router_id: 0xc0000201,
        area_id: 7,
        interface_id: 42,
        hello_interval: 11,
        dead_interval: 44,
        ..Default::default()
    });
    let built = crate::build::Builder::new(registry.clone())
        .build(packet, Addresses::default(), Default::default())
        .unwrap();
    let frame =
        crate::frame::Frame::without_timestamp(crate::frame::LinkType::ETHERNET, built.bytes)
            .unwrap();
    let decoded = crate::decode::Dissector::new(registry)
        .decode(frame, Default::default())
        .unwrap();
    let ospf = decoded
        .packet
        .get::<crate::protocol::network::ospfv3::Ospfv3>()
        .expect("OSPF survives the authentication header");
    assert_eq!(
        (ospf.router_id, ospf.area_id, ospf.interface_id),
        (0xc0000201, 7, 42)
    );
    assert_eq!((ospf.hello_interval, ospf.dead_interval), (11, 44));
    assert!(decoded.diagnostics.is_empty(), "{:?}", decoded.diagnostics);
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
    for (topic, payload) in [(b"a".as_slice(), b"x".as_slice()), (b"b", b"yz")] {
        packet.push(crate::protocol::application::mqtt::Mqtt {
            packet_type: 3,
            topic: Bytes::copy_from_slice(topic),
            payload: Bytes::copy_from_slice(payload),
            ..Default::default()
        });
    }
    let builder = crate::build::Builder::new(registry.clone());
    let built = builder
        .build(packet, Addresses::default(), Default::default())
        .unwrap();
    let messages = built
        .layout
        .layers
        .iter()
        .filter(|layer| layer.protocol.as_str() == "mqtt")
        .map(|layer| &built.bytes[layer.range.start..layer.range.end])
        .collect::<Vec<_>>();
    assert_eq!(
        messages,
        [b"\x30\x04\0\x01ax".as_slice(), b"\x30\x05\0\x01byz"]
    );
    let frame = crate::frame::Frame::without_timestamp(
        crate::frame::LinkType::ETHERNET,
        built.bytes.clone(),
    )
    .unwrap();
    let decoded = crate::decode::Dissector::new(registry)
        .decode(frame, Default::default())
        .unwrap();
    let messages = decoded
        .packet
        .iter()
        .filter_map(|layer| layer.downcast_ref::<crate::protocol::application::mqtt::Mqtt>())
        .map(|message| {
            (
                message.packet_type,
                message.topic.as_ref(),
                message.payload.as_ref(),
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(
        messages,
        [(3, b"a".as_slice(), b"x".as_slice()), (3, b"b", b"yz")]
    );
    let rebuilt = builder
        .build(decoded.packet, Addresses::default(), Default::default())
        .unwrap();
    assert_eq!(built.bytes, rebuilt.bytes);
}

#[test]
fn captures_convert_to_editable_documents_and_rebuild() {
    let manifest: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../../../examples/captures/protocols.manifest.json"
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
        let expected_wire = crate::layer::parse_hex(entry["wire_hex"].as_str().unwrap()).unwrap();
        assert!(original.ends_with(&expected_wire), "{name}");
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
        let expected_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join(entry["packet_document"].as_str().unwrap());
        let expected_json = std::fs::read_to_string(expected_path).unwrap();
        let expected = crate::document::Packet::parse(
            &expected_json,
            crate::document::Format::Json,
            expected_json.len(),
        )
        .unwrap();
        let actual = doc
            .layers
            .iter()
            .find(|layer| layer.protocol == name)
            .unwrap();
        let expected = expected
            .layers
            .iter()
            .find(|layer| layer.protocol == name)
            .unwrap();
        for (field, value) in &expected.fields {
            assert_eq!(actual.fields.get(field), Some(value), "{name}.{field}");
        }
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
    // https://datatracker.ietf.org/doc/html/rfc7252#section-3 checked 2026-10-25.
    round_trip(
        "coap",
        &[0x40, 1, 0, 1, 0xb1, b'x', 0x01, b'y'],
        &[
            ("message_id", 1_u16.into()),
            ("options[0].number", 11_u16.into()),
            ("options[0].value", Bytes::from_static(b"x").into()),
            ("options[1].number", 11_u16.into()),
            ("options[1].value", Bytes::from_static(b"y").into()),
        ],
    );
    // https://raw.githubusercontent.com/wireshark/wireshark/master/epan/dissectors/packet-cdp.c checked 2026-10-25.
    round_trip(
        "cdp",
        &[2, 180, 253, 99, 0, 99, 0, 5, 128],
        &[
            ("version", 2_u8.into()),
            ("tlvs[0].kind", 99_u16.into()),
            ("tlvs[0].value", Bytes::from_static(b"\x80").into()),
        ],
    );
}

#[test]
fn reference_packet_prefixes_are_bounded() {
    let registry = builtin::registry();
    let manifest: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../../../examples/captures/protocols.manifest.json"
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
