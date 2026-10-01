// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

mod common;

use std::sync::Arc;
use std::time::SystemTime;

use bytes::Bytes;
use common::packets::ipv4;
use packetcraftr_core::field::FieldValue;
use packetcraftr_core::frame::{Frame, LinkType};
use packetcraftr_core::layer::{Layer, Raw};
use packetcraftr_core::packet::Packet;
use packetcraftr_core::protocol::application::tftp::{MAX_OPTIONS, Tftp, TftpOption};
use packetcraftr_core::protocol::builtin;
use packetcraftr_core::protocol::transport::Udp;
use packetcraftr_core::registry::{Discriminator, Registry};
use packetcraftr_core::{build, codec, decode, expression};

const TRANSFER_PORT: u16 = 49_152;

/// UDP 69 plus the transfer port a `--decode-as` binding would add.
fn transfer_registry() -> Arc<Registry> {
    Arc::new(
        builtin::registry_with(|builder| {
            builder.bind("udp", u64::from(TRANSFER_PORT), "tftp", i32::MAX)?;
            Ok(())
        })
        .unwrap(),
    )
}

fn udp_packet(source_port: u16, destination_port: u16, payload: impl Layer) -> Packet {
    let mut packet = Packet::new();
    packet.push(ipv4([192, 0, 2, 1], [192, 0, 2, 2]));
    packet.push(Udp {
        source_port,
        destination_port,
        ..Udp::default()
    });
    packet.push(payload);
    packet
}

fn build_with(registry: &Arc<Registry>, packet: Packet, mode: codec::Mode) -> build::BuiltPacket {
    build::Builder::new(Arc::clone(registry))
        .build(
            packet,
            codec::Context::default(),
            build::Options {
                mode,
                ..build::Options::default()
            },
        )
        .expect("fixture builds")
}

fn dissect(registry: &Arc<Registry>, bytes: impl Into<Bytes>) -> decode::DecodedPacket {
    let frame = Frame::new(SystemTime::UNIX_EPOCH, LinkType::IPV4, bytes).unwrap();
    decode::Dissector::new(Arc::clone(registry))
        .decode(frame, decode::Options::default())
        .unwrap()
}

/// The UDP payload `message` carried over loopback-free documentation addresses.
fn datagram(message: &[u8], destination_port: u16) -> Bytes {
    build_with(
        &builtin::registry(),
        udp_packet(40_000, destination_port, Raw::new(message.to_vec())),
        codec::Mode::Permissive,
    )
    .bytes
}

/// Builds strictly, dissects, and requires a strict rebuild to match.
fn round_trip(
    registry: &Arc<Registry>,
    source_port: u16,
    destination_port: u16,
    message: Tftp,
) -> (Bytes, Tftp) {
    let built = build_with(
        registry,
        udp_packet(source_port, destination_port, message),
        codec::Mode::Strict,
    );
    let decoded = dissect(registry, built.bytes.clone());
    let layers = decoded
        .packet
        .iter()
        .map(|layer| layer.protocol_id().as_str())
        .collect::<Vec<_>>();
    assert_eq!(layers, ["ipv4", "udp", "tftp"]);
    let rebuilt = build_with(registry, decoded.packet.clone(), codec::Mode::Strict);
    assert_eq!(rebuilt.bytes, built.bytes);
    (built.bytes, decoded.packet.get::<Tftp>().unwrap().clone())
}

fn option(name: &str, value: &str) -> TftpOption {
    TftpOption {
        name: Bytes::copy_from_slice(name.as_bytes()),
        value: Bytes::copy_from_slice(value.as_bytes()),
    }
}

#[test]
fn read_request_with_options_round_trips_byte_exactly() {
    let registry = builtin::registry();
    let request = Tftp {
        opcode: 1,
        filename: Bytes::from_static(b"firmware.bin"),
        mode: Bytes::from_static(b"octet"),
        options: vec![option("blksize", "1024"), option("tsize", "0")],
        ..Tftp::default()
    };
    let (bytes, decoded) = round_trip(&registry, 40_000, 69, request.clone());
    assert_eq!(decoded, request);
    assert_eq!(
        &bytes[28..],
        b"\x00\x01firmware.bin\x00octet\x00blksize\x001024\x00tsize\x000\x00"
    );

    let write = Tftp {
        opcode: 2,
        filename: Bytes::from_static(b"upload.cfg"),
        mode: Bytes::from_static(b"netascii"),
        ..Tftp::default()
    };
    assert_eq!(round_trip(&registry, 40_000, 69, write.clone()).1, write);
}

#[test]
fn data_ack_error_and_oack_decode_on_the_transfer_port() {
    let registry = transfer_registry();
    let block = Tftp {
        opcode: 3,
        block: 1,
        data: Bytes::from(vec![0xa5; 512]),
        ..Tftp::default()
    };
    let (bytes, decoded) = round_trip(&registry, 69, TRANSFER_PORT, block.clone());
    assert_eq!(decoded, block);
    assert_eq!(&bytes[28..32], [0, 3, 0, 1]);
    assert_eq!(bytes.len(), 28 + 4 + 512);

    let ack = Tftp {
        opcode: 4,
        block: 1,
        ..Tftp::default()
    };
    assert_eq!(
        round_trip(&registry, TRANSFER_PORT, 40_000, ack.clone()).1,
        ack
    );

    let error = Tftp {
        opcode: 5,
        error_code: 1,
        error_message: Bytes::from_static(b"File not found"),
        ..Tftp::default()
    };
    let (bytes, decoded) = round_trip(&registry, 69, 40_000, error.clone());
    assert_eq!(decoded, error);
    assert_eq!(&bytes[28..], b"\x00\x05\x00\x01File not found\x00");

    let oack = Tftp {
        opcode: 6,
        options: vec![option("blksize", "1024")],
        ..Tftp::default()
    };
    assert_eq!(
        round_trip(&registry, TRANSFER_PORT, 40_000, oack.clone()).1,
        oack
    );

    // without the binding the same bytes stay raw
    let unbound = dissect(&builtin::registry(), datagram(&[0, 4, 0, 1], TRANSFER_PORT));
    assert!(unbound.packet.get::<Tftp>().is_none());
}

#[test]
fn strings_are_not_normalised_and_invalid_utf8_survives() {
    let registry = builtin::registry();
    let request = Tftp {
        opcode: 1,
        filename: Bytes::from_static(b"\xff\xfeDir/Mixed Case\xc3"),
        mode: Bytes::from_static(b"OcTeT"),
        options: vec![option("TSIZE", "")],
        ..Tftp::default()
    };
    let (_, decoded) = round_trip(&registry, 40_000, 69, request.clone());
    assert_eq!(decoded.filename, request.filename);
    assert_eq!(decoded.mode, request.mode);
    assert_eq!(decoded.options, request.options);
}

#[test]
fn malformed_and_out_of_scope_messages_decode_as_raw_with_bytes_intact() {
    let registry = builtin::registry();
    let mut too_many = b"\x00\x02f\x00octet\x00".to_vec();
    for _ in 0..=MAX_OPTIONS {
        too_many.extend_from_slice(b"k\x00v\x00");
    }
    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("unterminated filename", b"\x00\x01firmware.bin".to_vec()),
        ("unterminated mode", b"\x00\x01f\x00octet".to_vec()),
        ("unknown opcode", b"\x00\x09abc\x00".to_vec()),
        ("opcode zero", b"\x00\x00".to_vec()),
        ("one byte", vec![0]),
        ("truncated block", vec![0, 3, 0]),
        ("ack with trailing bytes", vec![0, 4, 0, 1, 9]),
        ("error without terminator", b"\x00\x05\x00\x01oops".to_vec()),
        (
            "error with trailing bytes",
            b"\x00\x05\x00\x01a\x00b".to_vec(),
        ),
        (
            "option without value",
            b"\x00\x01f\x00octet\x00blksize\x00".to_vec(),
        ),
        (
            "oack with a stray byte",
            b"\x00\x06blksize\x001\x00x".to_vec(),
        ),
        ("more options than the limit", too_many),
    ];
    for (label, message) in cases {
        let decoded = dissect(&registry, datagram(&message, 69));
        let layers = decoded
            .packet
            .iter()
            .map(|layer| layer.protocol_id().as_str())
            .collect::<Vec<_>>();
        assert_eq!(layers, ["ipv4", "udp", "raw"], "{label}");
        assert_eq!(
            decoded.packet.get::<Raw>().unwrap().bytes.as_ref(),
            message,
            "{label}"
        );
    }

    // exactly at the limit still decodes
    let mut at_limit = b"\x00\x02f\x00octet\x00".to_vec();
    for _ in 0..MAX_OPTIONS {
        at_limit.extend_from_slice(b"k\x00v\x00");
    }
    let decoded = dissect(&registry, datagram(&at_limit, 69));
    assert_eq!(
        decoded.packet.get::<Tftp>().unwrap().options.len(),
        MAX_OPTIONS
    );
}

#[test]
fn construction_refuses_what_the_wire_cannot_carry() {
    let registry = builtin::registry();
    let strict = |message: Tftp| {
        build::Builder::new(Arc::clone(&registry))
            .build(
                udp_packet(40_000, 69, message),
                codec::Context::default(),
                build::Options::default(),
            )
            .map(|built| built.bytes)
    };
    let request = || Tftp {
        filename: Bytes::from_static(b"f"),
        mode: Bytes::from_static(b"octet"),
        ..Tftp::default()
    };
    assert!(strict(request()).is_ok());
    for (label, message) in [
        (
            "NUL in the file name",
            Tftp {
                filename: Bytes::from_static(b"a\0b"),
                ..request()
            },
        ),
        (
            "NUL in an option value",
            Tftp {
                options: vec![option("k", "v\0")],
                ..request()
            },
        ),
        (
            "too many options",
            Tftp {
                options: (0..=MAX_OPTIONS).map(|_| option("k", "v")).collect(),
                ..request()
            },
        ),
        (
            "a file name on a DATA message",
            Tftp {
                opcode: 3,
                filename: Bytes::from_static(b"f"),
                ..Tftp::default()
            },
        ),
        (
            "an error code on an ACK",
            Tftp {
                opcode: 4,
                error_code: 2,
                ..Tftp::default()
            },
        ),
        (
            "an unknown opcode",
            Tftp {
                opcode: 9,
                ..Tftp::default()
            },
        ),
    ] {
        assert!(strict(message).is_err(), "{label}");
    }
}

#[test]
fn fields_are_reflective_and_recipes_build_tftp() {
    let registry = builtin::registry();
    let packet = expression::parse(
        "ipv4(source=192.0.2.1,destination=192.0.2.2)/udp(source_port=40000,destination_port=69)/tftp(opcode=1,filename=\"firmware.bin\",mode=\"octet\")",
        &registry,
        Default::default(),
    )
    .unwrap();
    let built = build::Builder::new(Arc::clone(&registry))
        .build(packet, Default::default(), Default::default())
        .unwrap();
    assert_eq!(&built.bytes[28..], b"\x00\x01firmware.bin\x00octet\x00");
    let decoded = dissect(&registry, built.bytes);
    let tftp = decoded.packet.get::<Tftp>().unwrap();
    assert_eq!(
        tftp.field("filename"),
        Some(FieldValue::Bytes(Bytes::from_static(b"firmware.bin")))
    );
    assert_eq!(tftp.field("opcode"), Some(FieldValue::Unsigned(1)));

    let mut layer = Tftp::default();
    assert!(
        layer
            .set_field("opcode", FieldValue::Unsigned(70_000))
            .is_err()
    );
    assert!(
        layer
            .set_field("filename", FieldValue::Unsigned(1))
            .is_err()
    );
    assert_eq!(
        registry
            .child_for("udp", Discriminator(69))
            .map(packetcraftr_core::layer::Id::as_str),
        Some("tftp")
    );
}
