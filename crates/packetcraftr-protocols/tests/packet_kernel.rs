// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Packet-kernel behaviour that can only be observed with concrete protocols
//! registered. The kernel itself stays free of built-in protocol dependencies,
//! so these cases live beside the implementations that supply them.

use std::sync::Arc;

use packetcraftr_model::{Frame, LinkType, ProviderId, RegistrationOrigin};
use packetcraftr_packet::catalog::{
    CatalogError, ProtocolBindingRegistration, ProtocolCatalogBuilder, ProtocolCatalogPolicy,
    ProtocolRegistrationSet,
};
use packetcraftr_packet::codec::Discriminator;
use packetcraftr_packet::decode::{DecodeOptions, Dissector};
use packetcraftr_packet::layer::ProtocolId;
use packetcraftr_protocols::builtin::{Module as BuiltinProtocols, catalog as default_catalog};

#[test]
fn builtin_binding_conflicts_require_an_exact_origin_selection() {
    let provider = ProviderId::from_static("example.native");
    let origin = RegistrationOrigin::Native {
        provider: provider.clone(),
    };
    let replacement = || {
        let mut set = ProtocolRegistrationSet::new();
        set.binding(ProtocolBindingRegistration::decode_only(
            ProtocolId::from_static("ethernet"),
            0x0800,
            ProtocolId::from_static("ipv6"),
            origin.clone(),
        ));
        set
    };

    let mut implicit = ProtocolCatalogBuilder::new();
    implicit.native_module(&BuiltinProtocols).unwrap();
    implicit.registration_set(replacement());
    let implicit = implicit.build().unwrap();
    assert_eq!(
        implicit.child_for(&ProtocolId::from_static("ethernet"), Discriminator(0x0800)),
        Some(&ProtocolId::from_static("ipv4"))
    );
    assert_eq!(
        implicit
            .binding_registration(&ProtocolId::from_static("ethernet"), Discriminator(0x0800))
            .unwrap()
            .origin,
        RegistrationOrigin::Builtin
    );

    let mut policy = ProtocolCatalogPolicy::new();
    policy.select_decode_binding(ProtocolId::from_static("ethernet"), 0x0800, origin.clone());
    let mut first = ProtocolCatalogBuilder::new();
    first.native_module(&BuiltinProtocols).unwrap();
    first.registration_set(replacement()).policy(policy.clone());
    let mut second = ProtocolCatalogBuilder::new();
    second.registration_set(replacement());
    second.native_module(&BuiltinProtocols).unwrap();
    second.policy(policy);
    let first = first.build().unwrap();
    let second = second.build().unwrap();

    assert_eq!(first.catalog_hash(), second.catalog_hash());
    assert_eq!(
        first.child_for(&ProtocolId::from_static("ethernet"), Discriminator(0x0800)),
        Some(&ProtocolId::from_static("ipv6"))
    );
    assert_eq!(
        first.discriminator_for(
            &ProtocolId::from_static("ethernet"),
            &ProtocolId::from_static("ipv6")
        ),
        Some(Discriminator(0x86dd))
    );
}

#[test]
fn build_still_rejects_an_unknown_shadowed_child() {
    let mut set = ProtocolRegistrationSet::new();
    set.binding(ProtocolBindingRegistration::decode_only(
        ProtocolId::from_static("ethernet"),
        0x0800,
        ProtocolId::from_static("example.unknown"),
        RegistrationOrigin::Native {
            provider: ProviderId::from_static("example.native"),
        },
    ));
    let mut builder = ProtocolCatalogBuilder::new();
    builder.native_module(&BuiltinProtocols).unwrap();
    builder.registration_set(set);

    assert!(matches!(
        builder.build(),
        Err(CatalogError::UnknownProtocol { protocol, .. })
            if protocol == ProtocolId::from_static("example.unknown")
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

    let catalog = Arc::new(default_catalog().unwrap());
    let frame = Frame::new(std::time::SystemTime::UNIX_EPOCH, LinkType::ETHERNET, bytes).unwrap();
    let decoded = Dissector::new(catalog)
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
            && diagnostic.severity == packetcraftr_packet::diagnostic::DiagnosticSeverity::Warning
            && diagnostic.layer == Some(2)
    }));
    assert!(
        !decoded
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "decode.trailing_padding")
    );
}
