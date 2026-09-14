// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
use bytes::Bytes;
use packetcraftr_core::{
    build::Builder,
    decode::Dissector,
    expression,
    field::FieldValue,
    filter,
    frame::{Frame, LinkType},
    layer::{Layer, Raw},
    protocol::{application::ntp::Ntp, builtin},
    template::{NumericRange, Template},
};
use std::time::UNIX_EPOCH;

fn build(expression_text: &str) -> packetcraftr_core::build::BuiltPacket {
    let registry = builtin::registry();
    let packet = expression::parse(expression_text, &registry, Default::default()).unwrap();
    Builder::new(registry)
        .build(packet, Default::default(), Default::default())
        .unwrap()
}

fn dissect(bytes: Bytes) -> packetcraftr_core::decode::DecodedPacket {
    Dissector::new(builtin::registry())
        .decode(
            Frame::new(UNIX_EPOCH, LinkType::IPV4, bytes).unwrap(),
            Default::default(),
        )
        .unwrap()
}

#[test]
fn ntp_client_messages_construct_decode_and_reencode_byte_exactly() {
    let built = build(concat!(
        "ipv4(source=192.0.2.1,destination=192.0.2.2)/udp(source_port=9000,destination_port=123)/",
        "ntp(version=4,mode=3,stratum=2,poll=6,precision=-20,",
        "reference_id=\"RATE\",root_delay=0x0102,root_dispersion=0x0304,",
        "transmit_timestamp=0xe6e123456789abcd,extensions=hex(\"dead\"))",
    ));
    let decoded = dissect(built.bytes.clone());
    let ntp = decoded.packet.get::<Ntp>().unwrap();
    assert_eq!(ntp.version, 4);
    assert_eq!(ntp.mode, 3);
    assert_eq!(ntp.poll, 6);
    assert_eq!(ntp.precision, -20);
    assert_eq!(ntp.reference_id.as_ref(), b"RATE");
    assert_eq!(ntp.transmit_timestamp, 0xe6e1_2345_6789_abcd);
    assert_eq!(ntp.extensions.as_ref(), &[0xde, 0xad]);
    assert_eq!(
        Builder::new(builtin::registry())
            .build(decoded.packet, Default::default(), Default::default())
            .unwrap()
            .bytes,
        built.bytes
    );
}

#[test]
fn ntp_server_and_broadcast_modes_round_trip() {
    for mode in [4_u8, 5] {
        let built = build(&format!(
            "ipv4(source=192.0.2.1,destination=192.0.2.2)/udp(source_port=123,destination_port=123)/ntp(mode={mode},stratum=2)"
        ));
        let decoded = dissect(built.bytes.clone());
        assert_eq!(decoded.packet.get::<Ntp>().unwrap().mode, mode);
        assert_eq!(
            Builder::new(builtin::registry())
                .build(decoded.packet, Default::default(), Default::default())
                .unwrap()
                .bytes,
            built.bytes
        );
    }
}

#[test]
fn ntp_construction_rejects_unsupported_versions_modes_and_bad_fields() {
    let registry = builtin::registry();
    for recipe in [
        "ntp(version=2)",
        "ntp(mode=6)",
        "ntp(mode=0)",
        "ntp(reference_id=hex(\"aabb\"))",
        "ipv4(source=192.0.2.1,destination=192.0.2.2)/udp(source_port=9000,destination_port=123)/ntp(mode=7)",
    ] {
        let parsed = expression::parse(recipe, &registry, Default::default());
        let rejected = match parsed {
            Err(_) => true,
            Ok(packet) => Builder::new(registry.clone())
                .build(packet, Default::default(), Default::default())
                .is_err(),
        };
        assert!(rejected, "{recipe} must be rejected");
    }
    // In strict mode a raw child cannot stand in for the typed message on the
    // bound port; permissive mode only warns.
    let packet = expression::parse(
        "ipv4(source=192.0.2.1,destination=192.0.2.2)/udp(source_port=9000,destination_port=123)/raw()",
        &registry,
        Default::default(),
    )
    .unwrap();
    let strict = Builder::new(registry.clone()).build(
        packet.clone(),
        Default::default(),
        Default::default(),
    );
    assert!(strict.is_err());
    let permissive = Builder::new(registry)
        .build(
            packet,
            Default::default(),
            packetcraftr_core::build::Options {
                mode: packetcraftr_core::codec::Mode::Permissive,
                ..Default::default()
            },
        )
        .unwrap();
    assert!(
        permissive
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "build.udp_encapsulation_port")
    );
}

#[test]
fn truncated_and_out_of_scope_wire_decodes_as_terminal_raw() {
    let built = build(
        "ipv4(source=192.0.2.1,destination=192.0.2.2)/udp(source_port=9000,destination_port=123)/ntp()",
    );
    let wire = built.bytes.to_vec();
    // Truncate inside the 48-byte base header; the UDP payload survives as raw.
    let mut truncated = wire.clone();
    truncated.truncate(wire.len() - 8);
    // Keep the length consistent so IPv4/UDP checksums still verify.
    let total = truncated.len() as u16;
    truncated[2..4].copy_from_slice(&total.to_be_bytes());
    let udp_total = (truncated.len() - 20) as u16;
    truncated[24..26].copy_from_slice(&udp_total.to_be_bytes());
    for wire in [
        truncated,
        {
            let mut control = wire.clone();
            control[28] = 0x26; // version 4, mode 6 (control message)
            control
        },
        {
            let mut legacy = wire.clone();
            legacy[28] = 0x13; // version 2, mode 3
            legacy
        },
    ] {
        let decoded = dissect(Bytes::from(wire));
        let raw = decoded.packet.get::<Raw>().unwrap();
        let ntp_offset = 20 + 8;
        assert_eq!(
            raw.bytes.as_ref(),
            &decoded.original[ntp_offset..],
            "unsupported or truncated NTP payload stays raw"
        );
        assert!(decoded.packet.get::<Ntp>().is_none());
    }
}

#[test]
fn ntp_fields_filter_templates_and_documents() {
    let registry = builtin::registry();
    let built = build(
        "ipv4(source=192.0.2.1,destination=192.0.2.2)/udp(source_port=9000,destination_port=123)/ntp(mode=4,stratum=2)",
    );
    let decoded = dissect(built.bytes.clone());
    let keep = filter::Filter::compile("ntp.mode == 4", &registry, Default::default()).unwrap();
    let drop = filter::Filter::compile("ntp.mode == 3", &registry, Default::default()).unwrap();
    for (filter, expected) in [(keep, true), (drop, false)] {
        assert_eq!(
            filter
                .matches(&filter::Context {
                    decoded: &decoded,
                    derived: &[],
                    number: 1,
                    tcp_stream: None,
                    udp_stream: None
                })
                .unwrap(),
            expected
        );
    }
    let packet = expression::parse(
        "ipv4(source=192.0.2.1,destination=192.0.2.2)/udp(source_port=9000,destination_port=123)/ntp()",
        &registry,
        Default::default(),
    )
    .unwrap();
    let template = Template::new(packet).axis(
        2,
        "stratum",
        NumericRange::new(1, 3, 1)
            .unwrap()
            .values()
            .collect::<Vec<FieldValue>>(),
    );
    let strata: Vec<u64> = template
        .expand(10)
        .unwrap()
        .map(|packet| {
            packet
                .unwrap()
                .get::<Ntp>()
                .unwrap()
                .field("stratum")
                .unwrap()
                .as_u64()
                .unwrap()
        })
        .collect();
    assert_eq!(strata, [1, 2, 3]);
}
