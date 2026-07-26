// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Packet-engine behaviour when composed with the built-in protocol module.

use std::sync::Arc;
use std::time::SystemTime;

use packetcraftr::capture::{Frame, LinkType};
use packetcraftr::packet::{
    decode::{Decoder, Options as DecodeOptions},
    diagnostic::Severity,
    layer::Id as ProtocolId,
    registry::{Builder as RegistryBuilder, Discriminator, Error as RegistryError},
};
use packetcraftr::protocol::builtin::{self, Module as BuiltinProtocols};

#[test]
fn build_canonicalizes_priority_winners_in_both_directions() {
    for candidates in [[("arp", 150), ("ipv6", 200)], [("ipv6", 200), ("arp", 150)]] {
        let mut builder = RegistryBuilder::new();
        builder.module(&BuiltinProtocols).unwrap();
        for (child, priority) in candidates {
            builder.bind("ethernet", 0x0800, child, priority).unwrap();
        }

        let registry = builder.build().unwrap();

        assert_eq!(
            registry.child_for("ethernet", Discriminator(0x0800)),
            Some(&ProtocolId::new("ipv6"))
        );
        assert_eq!(
            registry.discriminator_for("ethernet", "ipv6"),
            Some(Discriminator(0x0800))
        );
        assert_eq!(
            registry.discriminator_for("ethernet", "arp"),
            Some(Discriminator(0x0806))
        );
        assert_eq!(registry.discriminator_for("ethernet", "ipv4"), None);
    }
}

#[test]
fn build_still_rejects_an_unknown_shadowed_child() {
    let mut builder = RegistryBuilder::new();
    builder.module(&BuiltinProtocols).unwrap();
    builder
        .bind("ethernet", 0x0800, "example.unknown", 0)
        .unwrap();

    assert!(matches!(
        builder.build(),
        Err(RegistryError::UnknownProtocol { protocol })
            if protocol == ProtocolId::new("example.unknown")
    ));
}

#[test]
fn bytes_outside_udp_length_inside_ip_are_not_link_padding() {
    let mut bytes = vec![0_u8; 14 + 20 + 8 + 4];
    bytes[12..14].copy_from_slice(&0x0800_u16.to_be_bytes());
    let ip = 14;
    bytes[ip] = 0x45;
    bytes[ip + 2..ip + 4].copy_from_slice(&32_u16.to_be_bytes());
    bytes[ip + 8] = 64;
    bytes[ip + 9] = 17;
    bytes[ip + 12..ip + 16].copy_from_slice(&[192, 0, 2, 1]);
    bytes[ip + 16..ip + 20].copy_from_slice(&[198, 51, 100, 2]);
    let udp = ip + 20;
    bytes[udp..udp + 2].copy_from_slice(&1_u16.to_be_bytes());
    bytes[udp + 2..udp + 4].copy_from_slice(&2_u16.to_be_bytes());
    bytes[udp + 4..udp + 6].copy_from_slice(&8_u16.to_be_bytes());
    bytes[udp + 8..udp + 12].copy_from_slice(&[0xde, 0xad, 0xbe, 0xef]);

    let registry = Arc::new(builtin::registry().unwrap());
    let frame = Frame::new(SystemTime::UNIX_EPOCH, LinkType::ETHERNET, bytes).unwrap();
    let decoded = Decoder::new(registry)
        .decode(
            frame,
            DecodeOptions {
                verify_checksums: false,
                ..DecodeOptions::default()
            },
        )
        .unwrap();

    assert!(decoded.diagnostics.iter().any(|diagnostic| {
        diagnostic.code == "decode.trailing_malformed"
            && diagnostic.severity == Severity::Warning
            && diagnostic.layer == Some(2)
    }));
    assert!(
        !decoded
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "decode.trailing_padding")
    );
}
