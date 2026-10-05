// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use bytes::Bytes;
use packetcraftr_core::{
    build, codec, decode,
    frame::{Frame, LinkType},
    layer::{Malformed, Raw},
    packet::Packet,
    protocol::{
        application::dns::{self, Dns, Error as DecodeError, Limits, Name, RecordValue},
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
                mode: codec::Mode::Permissive,
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
fn bad_trunc_records_exact_bad_capture_bytes() {
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
        assert!(Dns::from_wire_with_limits(wire.clone(), Limits::default()).is_err());
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
fn encoding_reject_decoding_accepts() {
    let owner = Name::root();
    let txt = |count: usize| dns::Record {
        owner: owner.clone(),
        class: 1,
        ttl: 0,
        value: RecordValue::Txt(vec![Bytes::new(); count]),
    };
    let opt = |count: usize| {
        dns::Record::opt(dns::Edns {
            udp_payload_size: 1232,
            extended_response_code: 0,
            version: 0,
            dnssec_ok: false,
            flags: 0,
            options: vec![
                dns::EdnsOption {
                    code: 0,
                    data: Bytes::new()
                };
                count
            ],
        })
    };
    let encode = |record: dns::Record| {
        let mut message = Dns::default();
        message.additionals.push(record);
        message.to_wire()
    };
    for (accepted, refused, reason) in [
        (
            txt(dns::MAX_RECORDS),
            txt(dns::MAX_RECORDS + 1),
            "TXT string count exceeded",
        ),
        (opt(4_096), opt(4_097), "EDNS option count exceeded"),
    ] {
        assert!(encode(accepted).is_ok());
        let error = encode(refused).unwrap_err();
        assert!(
            matches!(
                &error,
                DecodeError::Encode(codec::Error::Invalid { message, .. }) if message == reason
            ),
            "{error:?}"
        );
    }
}
