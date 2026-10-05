// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
use crate::common;

use bytes::Bytes;
use common::packets::{build, dissect};
use packetcraftr_core::{
    build::Builder,
    expression,
    layer::Raw,
    protocol::{application::ntp::Ntp, builtin},
};

#[test]
fn ntp_build_reject_bad_fields() {
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
fn trunc_out_scope_wire_decodes_terminal_raw() {
    let built = build(
        "ipv4(source=192.0.2.1,destination=192.0.2.2)/udp(source_port=9000,destination_port=123)/ntp()",
    );
    let wire = built.bytes.to_vec();
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
            &decoded.frame.bytes()[ntp_offset..],
            "unsupported or truncated NTP payload stays raw"
        );
        assert!(decoded.packet.get::<Ntp>().is_none());
    }
}
