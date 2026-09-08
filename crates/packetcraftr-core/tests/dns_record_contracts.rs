// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use bytes::Bytes;
use packetcraftr_core::{
    Packet, build, decode,
    field::FieldValue,
    frame::{Frame, LinkType},
    layer::{Layer, Malformed, Raw},
    protocol::{
        application::dns::{DecodeError, DecodeLimits, Dns, Name, RecordValue, name},
        builtin,
        network::Ipv4,
        transport::Udp,
    },
};
use std::time::{Duration, UNIX_EPOCH};

fn question() -> Vec<u8> {
    let mut wire = vec![0x12, 0x34, 0x81, 0x80, 0, 1, 0, 0, 0, 0, 0, 0];
    wire.extend_from_slice(b"\x07example\x04test\0\0\x01\0\x01");
    wire
}

#[test]
fn malformed_names_retain_the_original_typed_cause() {
    use std::error::Error as _;

    for (suffix, expected) in [
        (
            &b"\x03a"[..],
            name::Error::TruncatedLabel {
                offset: 13,
                end: 16,
            },
        ),
        (&b"\xc0\x0c"[..], name::Error::SelfPointer { offset: 12 }),
        (
            &b"\x01a\xc0\x0c"[..],
            name::Error::PointerLoop { offset: 12 },
        ),
    ] {
        let mut wire = question();
        wire.truncate(12);
        wire.extend_from_slice(suffix);
        let error = Dns::from_wire_with_limits(wire, DecodeLimits::default()).unwrap_err();
        assert_eq!(error, DecodeError::Name(expected));
        assert_eq!(
            error.source().unwrap().downcast_ref::<name::Error>(),
            Some(&expected)
        );
        assert_eq!(error.to_string(), expected.to_string());
        assert!(packetcraftr_core::error::source_chain(&error).is_empty());
    }
}

fn record(wire: &mut Vec<u8>, owner: &[u8], kind: u16, class: u16, ttl: u32, data: &[u8]) {
    wire.extend_from_slice(owner);
    wire.extend_from_slice(&kind.to_be_bytes());
    wire.extend_from_slice(&class.to_be_bytes());
    wire.extend_from_slice(&ttl.to_be_bytes());
    wire.extend_from_slice(&u16::try_from(data.len()).unwrap().to_be_bytes());
    wire.extend_from_slice(data);
}

fn response() -> Vec<u8> {
    let mut wire = question();
    wire[6..12].copy_from_slice(&[0, 9, 0, 1, 0, 2]);
    for (kind, data) in [
        (1, vec![192, 0, 2, 8]),
        (
            28,
            "2001:db8::8"
                .parse::<std::net::Ipv6Addr>()
                .unwrap()
                .octets()
                .to_vec(),
        ),
        (5, vec![0xc0, 12]),
        (12, vec![0xc0, 12]),
        (15, vec![0, 10, 0xc0, 12]),
        (
            6,
            [
                vec![0xc0, 12, 0xc0, 12],
                (1u32..=5).flat_map(u32::to_be_bytes).collect(),
            ]
            .concat(),
        ),
        (33, vec![0, 1, 0, 2, 1, 187, 0xc0, 12]),
        (257, b"\x80\x03tag\0\xff".to_vec()),
        (16, b"\x03a\0\xff\0".to_vec()),
    ] {
        record(&mut wire, &[0xc0, 12], kind, 1, 123, &data);
    }
    record(&mut wire, &[0xc0, 12], 2, 1, 321, &[0xc0, 12]);
    record(
        &mut wire,
        &[0xc0, 12],
        65000,
        3,
        987,
        &[0xff, 0, 0xc0, 0xff],
    );
    record(
        &mut wire,
        &[0],
        41,
        1232,
        0x0100_8040,
        &[0, 12, 0, 3, 0, 0xff, 1],
    );
    wire
}

fn captured(message: &[u8]) -> Frame {
    let mut packet = Packet::new();
    packet.push(Ipv4 {
        source: "192.0.2.53".parse().unwrap(),
        destination: "198.51.100.8".parse().unwrap(),
        ..Ipv4::default()
    });
    packet.push(Udp {
        source_port: 53,
        destination_port: 49152,
        ..Udp::default()
    });
    packet.push(Raw::new(message.to_vec()));
    let built = build::Builder::new(builtin::registry())
        .build(
            packet,
            Default::default(),
            build::Options {
                mode: build::Mode::Permissive,
                ..Default::default()
            },
        )
        .unwrap();
    let mut frame = Frame::new(
        UNIX_EPOCH + Duration::new(123, 456789123),
        LinkType::IPV4,
        built.bytes,
    )
    .unwrap();
    frame.interface = Some(7);
    frame
}

#[test]
fn offline_records_edns_and_binary_data_are_typed_and_round_trip_exactly() {
    let wire = response();
    let frame = captured(&wire);
    let decoded = decode::Dissector::new(builtin::registry())
        .decode(frame.clone(), Default::default())
        .unwrap();
    assert_eq!(decoded.frame, frame);
    let dns = decoded.packet.get::<Dns>().unwrap();
    assert_eq!(dns.wire().as_ref(), wire);
    assert_eq!(dns.answers.len(), 9);
    assert_eq!(dns.authorities.len(), 1);
    assert_eq!(dns.additionals.len(), 2);
    assert_eq!(
        dns.answers[0].value,
        RecordValue::A("192.0.2.8".parse().unwrap())
    );
    assert_eq!(
        dns.answers[1].value,
        RecordValue::Aaaa("2001:db8::8".parse().unwrap())
    );
    assert_eq!(
        dns.answers[8].value,
        RecordValue::Txt(vec![Bytes::from_static(b"a\0\xff"), Bytes::new()])
    );
    assert_eq!(
        dns.additionals[0].value,
        RecordValue::Unknown {
            type_code: 65000,
            rdata: Bytes::from_static(&[0xff, 0, 0xc0, 0xff])
        }
    );
    let RecordValue::Opt(edns) = &dns.additionals[1].value else {
        panic!("OPT decoded")
    };
    assert_eq!(
        (
            edns.udp_payload_size,
            edns.extended_response_code,
            edns.version,
            edns.flags
        ),
        (1232, 1, 0, 0x8040)
    );
    assert!(edns.dnssec_ok);
    assert_eq!(edns.options[0].data.as_ref(), [0, 0xff, 1]);
    let FieldValue::List(additionals) = dns.field("additionals").unwrap() else {
        panic!("record list")
    };
    assert_eq!(
        additionals[0],
        FieldValue::List(vec![
            "example.test.".into(),
            65000u16.into(),
            3u16.into(),
            987u32.into(),
            FieldValue::List(vec![
                "unknown".into(),
                Bytes::from_static(&[0xff, 0, 0xc0, 0xff]).into()
            ])
        ])
    );
    let rebuilt = build::Builder::new(builtin::registry())
        .build(decoded.packet, Default::default(), Default::default())
        .unwrap();
    assert_eq!(&rebuilt.bytes, frame.bytes());
}

#[test]
fn malformed_and_truncated_records_remain_exact_malformed_capture_bytes() {
    let mut bad_length = question();
    bad_length[7] = 1;
    record(&mut bad_length, &[0xc0, 12], 1, 1, 0, &[192, 0, 2]);
    let mut trailing = question();
    trailing.push(0xff);
    let mut malformed_txt = question();
    malformed_txt[7] = 1;
    record(&mut malformed_txt, &[0xc0, 12], 16, 1, 0, &[5, 1]);
    let mut malformed_opt = question();
    malformed_opt[11] = 1;
    record(&mut malformed_opt, &[0], 41, 1232, 0, &[0, 1, 0]);
    let mut truncated = response();
    truncated.pop();
    let mut truncated_tc = truncated.clone();
    truncated_tc[2] |= 2;
    for wire in [
        bad_length,
        trailing,
        malformed_txt,
        malformed_opt,
        truncated,
        truncated_tc,
    ] {
        assert!(Dns::from_wire_with_limits(wire.clone(), DecodeLimits::default()).is_err());
        let frame = captured(&wire);
        let decoded = decode::Dissector::new(builtin::registry())
            .decode(frame.clone(), Default::default())
            .unwrap();
        assert!(decoded.packet.get::<Dns>().is_none());
        assert_eq!(
            decoded.packet.get::<Malformed>().unwrap().bytes.as_ref(),
            wire
        );
        assert!(!decoded.diagnostics.is_empty());
        let rebuilt = build::Builder::new(builtin::registry())
            .build(decoded.packet, Default::default(), Default::default())
            .unwrap();
        assert_eq!(&rebuilt.bytes, frame.bytes());
    }
}

#[test]
fn every_message_record_name_and_txt_bound_is_enforced() {
    let wire = response();
    let defaults = DecodeLimits::default();
    type Expected = fn(&DecodeError) -> bool;
    let cases: [(DecodeLimits, Expected); 5] = [
        (
            DecodeLimits {
                max_message_bytes: wire.len() - 1,
                ..defaults
            },
            |e| matches!(e, DecodeError::MessageTooLarge { .. }),
        ),
        (
            DecodeLimits {
                max_records: 11,
                ..defaults
            },
            |e| {
                matches!(
                    e,
                    DecodeError::RecordLimit {
                        actual: 12,
                        limit: 11
                    }
                )
            },
        ),
        (
            DecodeLimits {
                max_name_pointers: 0,
                ..defaults
            },
            |e| matches!(e, DecodeError::Name(name::Error::PointerLimit { limit: 0 })),
        ),
        (
            DecodeLimits {
                max_txt_strings: 1,
                ..defaults
            },
            |e| matches!(e, DecodeError::TxtStringLimit { limit: 1 }),
        ),
        (
            DecodeLimits {
                max_txt_bytes: 2,
                ..defaults
            },
            |e| matches!(e, DecodeError::TxtByteLimit { limit: 2 }),
        ),
    ];
    for (limits, expected) in cases {
        let error = Dns::from_wire_with_limits(wire.clone(), limits).unwrap_err();
        assert!(expected(&error), "{error:?}");
    }
    let exact = DecodeLimits {
        max_message_bytes: wire.len(),
        max_records: 12,
        max_name_pointers: 1,
        max_txt_strings: 2,
        max_txt_bytes: 3,
    };
    assert!(Dns::from_wire_with_limits(wire, exact).is_ok());
    let mut questions = question();
    questions[4..6].copy_from_slice(&65u16.to_be_bytes());
    assert!(matches!(
        Dns::from_wire_with_limits(questions, defaults),
        Err(DecodeError::QuestionLimit {
            actual: 65,
            limit: 64
        })
    ));
    let mut overlong = question();
    overlong.truncate(12);
    for _ in 0..4 {
        overlong.push(63);
        overlong.extend_from_slice(&[b'a'; 63]);
    }
    overlong.extend_from_slice(&[0, 0, 1, 0, 1]);
    assert!(matches!(
        Dns::from_wire_with_limits(overlong, defaults),
        Err(DecodeError::Name(name::Error::NameTooLong))
    ));
    assert!(matches!(
        Name::from_labels(std::iter::repeat(Bytes::from_static(b"a"))),
        Err(DecodeError::Name(name::Error::NameTooLong))
    ));
    let unbounded = DecodeLimits {
        max_message_bytes: usize::MAX,
        ..defaults
    };
    assert!(matches!(
        Dns::from_wire_with_limits(vec![0; 65_536], unbounded),
        Err(DecodeError::MessageTooLarge {
            maximum: 65_535,
            ..
        })
    ));
}

#[test]
fn offline_opt_version_and_section_are_wire_facts_and_changed_names_cannot_reencode() {
    let mut wire = question();
    wire[7] = 1;
    record(&mut wire, &[0xc0, 12], 41, 512, 0x0001_8000, &[]);
    let dns = Dns::from_wire(wire).unwrap();
    let RecordValue::Opt(edns) = &dns.answers[0].value else {
        panic!("OPT stays in answer section")
    };
    assert_eq!(edns.version, 1);
    let mut dns = Dns::from_wire(response()).unwrap();
    dns.answers[0].owner = Name::from_labels(["EXAMPLE", "test"]).unwrap();
    let mut packet = Packet::new();
    packet.push(dns);
    assert!(
        build::Builder::new(builtin::registry())
            .build(packet, Default::default(), Default::default())
            .is_err()
    );
}

#[test]
fn non_in_a_records_remain_exact_unknown_rdata_for_compressed_and_full_names() {
    // CH A carries a domain name plus a 16-bit address, not an IPv4 address.
    for data in [
        vec![0xc0, 12, 0, 1],
        b"\x07example\x04test\0\0\x01".to_vec(),
    ] {
        for class in [3, 65000] {
            let mut wire = question();
            wire[7] = 1;
            record(&mut wire, &[0xc0, 12], 1, class, 123, &data);
            let frame = captured(&wire);
            let decoded = decode::Dissector::new(builtin::registry())
                .decode(frame.clone(), Default::default())
                .unwrap();
            let dns = decoded.packet.get::<Dns>().unwrap();
            assert_eq!(dns.answers[0].class, class);
            assert_eq!(
                dns.answers[0].value,
                RecordValue::Unknown {
                    type_code: 1,
                    rdata: Bytes::copy_from_slice(&data)
                }
            );
            let rebuilt = build::Builder::new(builtin::registry())
                .build(decoded.packet, Default::default(), Default::default())
                .unwrap();
            assert_eq!(&rebuilt.bytes, frame.bytes());
        }
    }
}
