// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
mod common;
use bytes::Bytes;
use common::packets::{ROOT_LINK_TYPE, rooted_registry};
use packetcraftr_core::{
    build, codec, decode, document,
    field::FieldValue,
    filter::{Filter, Limits},
    frame::Frame,
    layer::{Layer, Padding, Raw},
    packet::Packet,
    protocol::{
        application::{
            http::{BodyDecoder, Framing, Header, Http, StartLine},
            mqtt::Mqtt,
            rtcp::{Contents, Packet as RtcpPacket, Report, Rtcp, SdesChunk, SdesItem},
            rtp::Rtp,
            tftp::{OptionPair, Tftp},
        },
        builtin,
        link::{Ethernet, Llc, Lldp, LldpTlv, Stp},
    },
};
use std::{collections::BTreeMap, sync::Arc, time::UNIX_EPOCH};
fn built(packet: Packet) -> build::BuiltPacket {
    build::Builder::new(builtin::registry())
        .build(packet, codec::Context::default(), build::Options::default())
        .unwrap()
}
fn roundtrip(layer: impl Layer) -> decode::DecodedPacket {
    let protocol = *layer.protocol_id();
    let mut packet = Packet::new();
    packet.push(layer);
    let first = built(packet);
    // Generic packet documents retain every field needed to reconstruct constructed bytes.
    let document = document::Packet::from_packet(&first.packet);
    let rebuilt = built(document.to_packet(&builtin::registry(), 64).unwrap());
    assert_eq!(first.bytes, rebuilt.bytes);
    let registry = rooted_registry(protocol.as_str());
    let decoded = decode::Dissector::new(registry)
        .decode(
            Frame::new(UNIX_EPOCH, ROOT_LINK_TYPE, first.bytes.clone()).unwrap(),
            decode::Options::default(),
        )
        .unwrap();
    assert!(
        decoded.diagnostics.is_empty(),
        "{}: {:?}",
        protocol,
        decoded.diagnostics
    );
    let document = document::Packet::from_packet(&decoded.packet);
    let rebuilt = built(document.to_packet(&builtin::registry(), 64).unwrap());
    assert_eq!(first.bytes, rebuilt.bytes);
    decoded
}
#[test]
fn lldp_mandatory_unknown_and_padding_values_roundtrip_and_bind() {
    let mut lldp = Lldp::new(
        4,
        Bytes::from_static(&[2, 0, 0, 0, 0, 1]),
        5,
        Bytes::from_static(b"eth0"),
        120,
    );
    lldp.tlvs.push(LldpTlv {
        kind: 9,
        value: Bytes::from_static(&[255, 0, 128]),
    });
    lldp.tlvs.push(LldpTlv {
        kind: 5,
        value: Bytes::from_static(b"fixture"),
    });
    roundtrip(lldp.clone());
    let mut packet = Packet::new();
    packet.push(Ethernet::default());
    packet.push(lldp);
    packet.push(Padding::new(vec![0; 8]));
    let first = built(packet);
    assert_eq!(&first.bytes[12..14], &[0x88, 0xcc]);
    let decoded = decode::Dissector::new(builtin::registry())
        .decode(
            Frame::new(
                UNIX_EPOCH,
                packetcraftr_core::frame::LinkType::ETHERNET,
                first.bytes,
            )
            .unwrap(),
            decode::Options::default(),
        )
        .unwrap();
    assert!(decoded.packet.iter().any(<dyn Layer>::is::<Lldp>));
    let context = packetcraftr_core::filter::Context {
        decoded: &decoded,
        derived: &[],
        number: 1,
        tcp_stream: None,
        udp_stream: None,
    };
    assert!(
        Filter::compile(
            "lldp.tlvs[3].kind == 9",
            &builtin::registry(),
            Limits::default()
        )
        .unwrap()
        .matches(&context)
        .unwrap()
    );
}
#[test]
fn all_stp_bpdu_forms_roundtrip_and_llc_selects_stp() {
    for layer in [Stp::default(), Stp::topology_change(), Stp::rapid()] {
        roundtrip(layer);
    }
    let mut packet = Packet::new();
    packet.push(Ethernet::default());
    packet.push(Llc {
        dsap: 0x42,
        ssap: 0x42,
        ..Llc::default()
    });
    packet.push(Stp::rapid());
    let first = built(packet);
    let decoded = decode::Dissector::new(builtin::registry())
        .decode(
            Frame::new(
                UNIX_EPOCH,
                packetcraftr_core::frame::LinkType::ETHERNET,
                first.bytes,
            )
            .unwrap(),
            decode::Options::default(),
        )
        .unwrap();
    assert!(decoded.packet.iter().any(<dyn Layer>::is::<Stp>));
}
#[test]
fn tftp_all_six_opcodes_and_option_pairs_roundtrip() {
    for opcode in 1..=6 {
        let options = if matches!(opcode, 1 | 2 | 6) {
            vec![OptionPair {
                name: Bytes::from_static(b"blksize"),
                value: Bytes::from_static(b"1024"),
            }]
        } else {
            Vec::new()
        };
        roundtrip(Tftp {
            opcode,
            block: 65535,
            data: if opcode == 3 {
                Bytes::from_static(&[0, 255, 128])
            } else {
                Bytes::new()
            },
            options,
            error_message: Bytes::from_static(b"missing"),
            ..Tftp::default()
        });
    }
    assert_eq!(
        builtin::registry()
            .child_for("udp", packetcraftr_core::registry::Discriminator(69))
            .unwrap()
            .as_str(),
        "tftp"
    );
}
#[test]
fn tftp_request_modes_validate_against_rfc1350_in_construction_and_decode() {
    let registry = builtin::registry();
    let context = codec::LayerDecodeContext {
        parent: None,
        registry: &registry,
        network: None,
        discriminator: None,
    };
    for mode in [b"netascii".as_slice(), b"OCTET", b"Mail"] {
        roundtrip(Tftp {
            mode: Bytes::copy_from_slice(mode),
            ..Tftp::default()
        });
    }
    for opcode in [1u16, 2] {
        let mut packet = Packet::new();
        packet.push(Tftp {
            opcode,
            mode: Bytes::from_static(b"bogus"),
            ..Tftp::default()
        });
        assert!(
            build::Builder::new(Arc::clone(&registry))
                .build(packet, Default::default(), Default::default())
                .is_err(),
            "opcode={opcode}"
        );
        let mut wire = opcode.to_be_bytes().to_vec();
        wire.extend_from_slice(b"file\0bogus\0");
        assert!(
            registry
                .codec("tftp")
                .unwrap()
                .decode(wire.into(), &context)
                .is_err(),
            "opcode={opcode}"
        );
    }
    roundtrip(Tftp {
        opcode: 6,
        mode: Bytes::from_static(b"bogus"),
        options: vec![OptionPair {
            name: Bytes::from_static(b"blksize"),
            value: Bytes::from_static(b"1024"),
        }],
        ..Tftp::default()
    });
}
#[test]
fn rtp_keeps_csrc_extension_and_nonzero_padding_exact() {
    roundtrip(Rtp {
        marker: true,
        payload_type: 96,
        sequence: 65535,
        timestamp: u32::MAX,
        ssrc: 42,
        csrcs: vec![1, 2],
        extension_present: true,
        extension_profile: 0xbede,
        extension: Bytes::from_static(&[1, 2, 3, 4]),
        payload: Bytes::from_static(&[0, 128, 255]),
        padding: Bytes::from_static(&[0xff, 2]),
    });
    roundtrip(Rtp {
        extension_present: true,
        ..Rtp::default()
    });
}
#[test]
fn rtcp_reports_sdes_bye_and_unknown_packets_roundtrip() {
    let report = Report {
        ssrc: 2,
        fraction_lost: 3,
        cumulative_lost: -7,
        highest_sequence: u32::MAX,
        jitter: 8,
        last_sr: 9,
        delay_since_sr: 10,
    };
    let sr = RtcpPacket::sender_report(1, 2, 3, 4, 5, std::slice::from_ref(&report)).unwrap();
    assert!(
        matches!(sr.contents().unwrap(),Contents::SenderReport {reports,..} if reports==vec![report])
    );
    let packets = vec![
        sr,
        RtcpPacket::receiver_report(2, &[]).unwrap(),
        RtcpPacket::source_description(&[SdesChunk {
            ssrc: 2,
            items: vec![
                SdesItem {
                    kind: 1,
                    value: Bytes::from_static(b"test"),
                },
                SdesItem {
                    kind: 99,
                    value: Bytes::from_static(&[0, 255]),
                },
            ],
        }])
        .unwrap(),
        RtcpPacket::bye(&[2], Some(Bytes::from_static(b"done"))).unwrap(),
        RtcpPacket {
            packet_type: 210,
            count: 1,
            body: Bytes::from_static(&[1, 2, 3, 4]),
            padding: Bytes::new(),
        },
    ];
    roundtrip(Rtcp { packets });
}
#[test]
fn mqtt_controls_roundtrip_and_parse_publication_metadata() {
    roundtrip(Mqtt::connect("fixture", 60).unwrap());
    let publish = Mqtt::publish(
        "sensor/temperature",
        Bytes::from_static(&[0, 128, 255]),
        1,
        Some(7),
        true,
    )
    .unwrap();
    assert_eq!(publish.fields().unwrap().packet_id, Some(7));
    roundtrip(publish);
    for kind in 4..=7 {
        roundtrip(Mqtt::acknowledgement(kind, 7).unwrap());
    }
    roundtrip(Mqtt::subscribe(7, &[("sensor/#", 1)]).unwrap());
    for kind in [2, 9, 10, 11, 12, 13, 14] {
        let body = match kind {
            2 => Bytes::from_static(&[0, 0]),
            9 => Bytes::from_static(&[0, 7, 1]),
            10 => Bytes::from_static(&[0, 7, 0, 1, b'x']),
            11 => Bytes::from_static(&[0, 7]),
            _ => Bytes::new(),
        };
        roundtrip(Mqtt {
            packet_type: kind,
            flags: if kind == 10 { 2 } else { 0 },
            body,
        });
    }
}
#[test]
fn structured_http_derives_length_or_chunking_and_rejects_header_injection() {
    let start = StartLine::Response {
        version: "HTTP/1.1".to_owned(),
        status: 200,
        reason: Bytes::from_static(b"OK"),
    };
    for framing in [Framing::ContentLength, Framing::Chunked] {
        let layer = Http::new(
            start.clone(),
            vec![
                Header {
                    name: "X-Order".to_owned(),
                    value: Bytes::from_static(b"first"),
                },
                Header {
                    name: "Content-Length".to_owned(),
                    value: Bytes::from_static(b"999"),
                },
            ],
            Bytes::from_static(b"body"),
            framing,
        )
        .unwrap();
        let mut decoder = BodyDecoder::new(layer.head().body(None).unwrap(), 16);
        assert!(decoder.consume(layer.constructed_body()).unwrap().complete);
        assert_eq!(decoder.body_bytes(), 4);
        roundtrip(layer);
    }
    assert!(
        Http::new(
            start,
            vec![Header {
                name: "X".to_owned(),
                value: Bytes::from_static(b"a\r\nInjected: b")
            }],
            Bytes::new(),
            Framing::ContentLength
        )
        .is_err()
    );
    assert!(
        Http::new(
            StartLine::Request {
                method: "POST".to_owned(),
                target: Bytes::from_static(b"/"),
                version: "HTTP/1.0".to_owned()
            },
            Vec::new(),
            Bytes::new(),
            Framing::Chunked
        )
        .is_err()
    );
    let fields = BTreeMap::from([
        ("method".to_owned(), FieldValue::Text("POST".to_owned())),
        (
            "target".to_owned(),
            FieldValue::Bytes(Bytes::from_static(b"/test")),
        ),
        (
            "body".to_owned(),
            FieldValue::Bytes(Bytes::from_static(b"abc")),
        ),
    ]);
    let layer = builtin::registry()
        .codec("http")
        .unwrap()
        .make_layer(&fields)
        .unwrap();
    assert_eq!(
        layer.field("method"),
        Some(FieldValue::Text("POST".to_owned()))
    );
}

#[test]
fn constructed_http_rejects_payload_children_while_parsed_heads_accept_bodies() {
    for start in [
        StartLine::Request {
            method: "GET".to_owned(),
            target: Bytes::from_static(b"/"),
            version: "HTTP/1.1".to_owned(),
        },
        StartLine::Response {
            version: "HTTP/1.1".to_owned(),
            status: 204,
            reason: Bytes::from_static(b"No Content"),
        },
    ] {
        let mut packet = Packet::new();
        packet.push(Http::new(start, Vec::new(), Bytes::new(), Framing::ContentLength).unwrap());
        packet.push(Raw::new(b"extra".to_vec()));
        assert!(
            build::Builder::new(builtin::registry())
                .build(packet, Default::default(), Default::default())
                .is_err()
        );
    }
    let mut packet = Packet::new();
    packet.push(
        Http::new(
            StartLine::Request {
                method: "POST".to_owned(),
                target: Bytes::from_static(b"/"),
                version: "HTTP/1.1".to_owned(),
            },
            Vec::new(),
            Bytes::from_static(b"abc"),
            Framing::ContentLength,
        )
        .unwrap(),
    );
    packet.push(Raw::new(b"extra".to_vec()));
    assert!(
        build::Builder::new(builtin::registry())
            .build(packet, Default::default(), Default::default())
            .is_err()
    );
    let fields = BTreeMap::from([
        (
            "wire".to_owned(),
            FieldValue::Bytes(Bytes::from_static(
                b"POST / HTTP/1.1\r\nContent-Length: 3\r\n\r\n",
            )),
        ),
        (
            "body".to_owned(),
            FieldValue::Bytes(Bytes::from_static(b"abc")),
        ),
    ]);
    let mut packet = Packet::new();
    packet.push_boxed(
        builtin::registry()
            .codec("http")
            .unwrap()
            .make_layer(&fields)
            .unwrap(),
    );
    packet.push(Raw::new(b"extra".to_vec()));
    assert!(
        build::Builder::new(builtin::registry())
            .build(packet, Default::default(), Default::default())
            .is_err()
    );
    // A wire-parsed header still takes its body from the payload layer, so a
    // decoded header and body rebuild to identical bytes.
    let mut packet = Packet::new();
    packet
        .push(Http::try_from(b"POST / HTTP/1.1\r\nContent-Length: 5\r\n\r\n".as_slice()).unwrap());
    packet.push(Raw::new(b"extra".to_vec()));
    let first = built(packet);
    assert!(first.bytes.ends_with(b"extra"));
    let decoded = decode::Dissector::new(rooted_registry("http"))
        .decode(
            Frame::new(UNIX_EPOCH, ROOT_LINK_TYPE, first.bytes.clone()).unwrap(),
            decode::Options::default(),
        )
        .unwrap();
    let document = document::Packet::from_packet(&decoded.packet);
    let rebuilt = built(document.to_packet(&builtin::registry(), 64).unwrap());
    assert_eq!(first.bytes, rebuilt.bytes);
    // Packet documents preserve construction provenance: a constructed
    // empty-body message still rejects a payload child after a document
    // roundtrip, while a parsed head omits the constructed body field and
    // keeps accepting payload layers.
    let mut packet = Packet::new();
    packet.push(
        Http::new(
            StartLine::Request {
                method: "GET".to_owned(),
                target: Bytes::from_static(b"/"),
                version: "HTTP/1.1".to_owned(),
            },
            Vec::new(),
            Bytes::new(),
            Framing::ContentLength,
        )
        .unwrap(),
    );
    let document = document::Packet::from_packet(&built(packet).packet);
    assert!(document.layers[0].fields.contains_key("body"));
    let mut rebuilt = document.to_packet(&builtin::registry(), 64).unwrap();
    rebuilt.push(Raw::new(b"extra".to_vec()));
    assert!(
        build::Builder::new(builtin::registry())
            .build(rebuilt, Default::default(), Default::default())
            .is_err()
    );
    let mut packet = Packet::new();
    packet.push(Http::try_from(b"GET / HTTP/1.1\r\n\r\n".as_slice()).unwrap());
    packet.push(Raw::new(b"extra".to_vec()));
    let first = built(packet);
    let document = document::Packet::from_packet(&first.packet);
    assert!(!document.layers[0].fields.contains_key("body"));
    let rebuilt = built(document.to_packet(&builtin::registry(), 64).unwrap());
    assert_eq!(first.bytes, rebuilt.bytes);
}

#[test]
fn http_header_capacity_counts_retained_and_derived_headers() {
    use packetcraftr_core::protocol::application::http::{Error, Limit, MAX_HEADERS};
    let headers = || {
        vec![
            Header {
                name: "X".into(),
                value: Bytes::from_static(b"a")
            };
            MAX_HEADERS
        ]
    };
    let start = |status| StartLine::Response {
        version: "HTTP/1.1".into(),
        status,
        reason: Bytes::new(),
    };
    for framing in [Framing::ContentLength, Framing::Chunked] {
        for name in ["Content-Length", "Transfer-Encoding"] {
            let mut supplied = headers();
            supplied[0].name = name.into();
            let layer = Http::new(start(200), supplied, Bytes::new(), framing).unwrap();
            assert_eq!(layer.head().headers.len(), MAX_HEADERS);
        }
        assert!(matches!(
            Http::new(start(200), headers(), Bytes::new(), framing),
            Err(Error::Limit(Limit::HeaderCount))
        ));
    }
    assert_eq!(
        Http::new(start(204), headers(), Bytes::new(), Framing::ContentLength)
            .unwrap()
            .head()
            .headers
            .len(),
        MAX_HEADERS
    );
}

#[test]
fn mqtt_topic_filters_validate_wildcards_in_construction_and_wire_decode() {
    let registry = builtin::registry();
    let context = codec::LayerDecodeContext {
        parent: None,
        registry: &registry,
        network: None,
        discriminator: None,
    };
    for (topic, valid) in [
        ("#", true),
        ("+", true),
        ("a/+/b/#", true),
        ("/+/", true),
        ("foo#bar", false),
        ("a+b", false),
        ("a/#/b", false),
        ("##", false),
        ("a/+b", false),
        ("", false),
    ] {
        assert_eq!(Mqtt::subscribe(1, &[(topic, 0)]).is_ok(), valid, "{topic}");
        for kind in [8, 10] {
            let mut body = vec![0, 1];
            body.extend_from_slice(&(topic.len() as u16).to_be_bytes());
            body.extend_from_slice(topic.as_bytes());
            if kind == 8 {
                body.push(0);
            }
            let mut wire = vec![(kind << 4) | 2, body.len() as u8];
            wire.extend(body);
            assert_eq!(
                registry
                    .codec("mqtt")
                    .unwrap()
                    .decode(wire.into(), &context)
                    .is_ok(),
                valid,
                "kind={kind} {topic}"
            );
        }
    }
}

#[test]
fn lldp_management_address_length_is_bounded_in_construction_and_decode() {
    let registry = builtin::registry();
    let context = codec::LayerDecodeContext {
        parent: None,
        registry: &registry,
        network: None,
        discriminator: None,
    };
    let base = built({
        let mut packet = Packet::new();
        packet.push(Lldp::default());
        packet
    })
    .bytes;
    for length in [1u8, 2, 31, 32, 255] {
        let mut value = vec![0; usize::from(length) + 7];
        value[0] = length;
        value[1] = 1;
        let mut layer = Lldp::default();
        layer.tlvs.push(LldpTlv {
            kind: 8,
            value: value.clone().into(),
        });
        let mut packet = Packet::new();
        packet.push(layer);
        assert_eq!(
            build::Builder::new(registry.clone())
                .build(packet, Default::default(), Default::default())
                .is_ok(),
            (2..=31).contains(&length),
            "length={length}"
        );
        let mut wire = base[..base.len() - 2].to_vec();
        wire.extend_from_slice(&((8u16 << 9) | value.len() as u16).to_be_bytes());
        wire.extend(value);
        wire.extend([0, 0]);
        assert_eq!(
            registry
                .codec("lldp")
                .unwrap()
                .decode(wire.into(), &context)
                .is_ok(),
            (2..=31).contains(&length),
            "length={length}"
        );
    }
}
#[test]
fn malformed_truncated_and_oversized_messages_fail_or_preserve_raw_bytes() {
    let registry = builtin::registry();
    for (protocol, wire) in [
        ("lldp", vec![0, 0]),
        ("lldp", vec![2, 4, 7]),
        ("stp", vec![0, 0, 2, 2]),
        ("tftp", vec![0, 1, b'x']),
        ("tftp", vec![0, 4, 0, 1, 0]),
        ("rtp", vec![0x80; 11]),
        ("rtp", vec![0xa0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
        ("rtcp", vec![0x80, 200, 0, 1, 0, 0, 0, 0]),
        ("mqtt", vec![0x10, 0xff, 0xff, 0xff, 0xff]),
        ("mqtt", vec![0x30, 2, 0, 0]),
    ] {
        let context = codec::LayerDecodeContext {
            parent: None,
            registry: &registry,
            network: None,
            discriminator: None,
        };
        assert!(
            registry
                .codec(protocol)
                .unwrap()
                .decode(wire.into(), &context)
                .is_err(),
            "{protocol}"
        );
    }
    let context = codec::LayerDecodeContext {
        parent: None,
        registry: &registry,
        network: None,
        discriminator: None,
    };
    let partial = Bytes::from_static(&[0x30, 10, 0]);
    let decoded = registry
        .codec("mqtt")
        .unwrap()
        .decode(partial.clone(), &context)
        .unwrap();
    assert_eq!(
        decoded.layer.field("bytes"),
        Some(FieldValue::Bytes(partial))
    );
    let huge = Bytes::from(vec![0u8; 1024 * 1024]);
    assert!(
        Mqtt {
            packet_type: 3,
            flags: 0,
            body: huge
        }
        .fields()
        .is_err()
    );
    let mut lldp = Lldp::default();
    lldp.tlvs.extend((0..254).map(|_| LldpTlv {
        kind: 9,
        value: Bytes::new(),
    }));
    let mut packet = Packet::new();
    packet.push(lldp);
    assert!(
        build::Builder::new(Arc::clone(&registry))
            .build(packet, Default::default(), Default::default())
            .is_err()
    );
}

#[test]
fn optional_protocol_fields_do_not_invent_values_absent_from_the_wire() {
    assert_eq!(Tftp::ack(7).field("filename"), None);
    assert_eq!(Tftp::ack(7).field("mode"), None);
    assert_eq!(Tftp::default().field("block"), None);
    assert_eq!(Stp::topology_change().field("root_id"), None);
    assert_eq!(Stp::topology_change().field("flags"), None);
    assert_eq!(Stp::default().field("version1_length"), None);
    assert_eq!(Rtp::default().field("extension_profile"), None);
    assert_eq!(Rtp::default().field("extension"), None);
    assert_eq!(Rtp::default().field("padding"), None);
}
