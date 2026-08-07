// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use packetcraftr_packet::{
    Packet, document,
    layer::{Padding, Raw},
    registry::{Builder, Error as RegistryError},
};

#[test]
fn packet_edits_preserve_padding_boundaries() {
    let mut packet = Packet::new();
    packet.push(Raw::new(vec![1_u8, 2]));
    packet.push(Padding::after_layer(vec![0_u8; 2], 1));

    packet
        .insert(0, Raw::new(vec![9_u8]))
        .expect("insertion should succeed");
    assert_eq!(
        packet
            .get::<Padding>()
            .and_then(|padding| padding.outside_layer),
        Some(2)
    );

    let error = packet
        .remove(2)
        .expect_err("removing a referenced padding boundary must fail closed");
    assert!(matches!(
        error,
        packetcraftr_packet::Error::PaddingBoundaryRemoval { index: 2 }
    ));
}

#[test]
fn registry_rejects_conflicting_roots_and_bindings() {
    let mut builder = Builder::new();
    builder
        .bind_link_type(1, "raw")
        .expect("first root binding should succeed");
    assert!(matches!(
        builder.bind_link_type(1, "other"),
        Err(RegistryError::DuplicateLinkType { link_type: 1 })
    ));

    let mut builder = Builder::new();
    builder
        .bind("parent", 7, "first", 10)
        .expect("first child binding should succeed");
    assert!(matches!(
        builder.bind("parent", 7, "second", 10),
        Err(RegistryError::BindingConflict {
            discriminator: 7,
            priority: 10,
            ..
        })
    ));
}

#[test]
fn unresolved_registry_references_are_rejected_at_finalization() {
    let mut builder = Builder::new();
    builder
        .bind_link_type(101, "missing")
        .expect("binding is staged until finalization");
    assert!(matches!(
        builder.build(),
        Err(RegistryError::UnknownProtocol { protocol }) if protocol.as_str() == "missing"
    ));
}

#[test]
fn packet_documents_enforce_byte_layer_and_duplicate_key_limits() {
    let minimal = r#"{"schema":"packetcraftr.packet/v1","layers":[]}"#;
    assert!(matches!(
        document::Packet::parse(minimal, document::Format::Json, minimal.len() - 1),
        Err(document::Error::SizeLimit { .. })
    ));

    let one_layer = r#"{"schema":"packetcraftr.packet/v1","layers":[{"protocol":"raw"}]}"#;
    assert!(matches!(
        document::Packet::parse_with_resource_limits(
            one_layer,
            document::Format::Json,
            one_layer.len(),
            0,
            document::DEFAULT_MAX_DOCUMENT_NESTING,
        ),
        Err(document::Error::LayerLimit { limit: 0 })
    ));

    let duplicate = "schema: packetcraftr.packet/v1\nschema: duplicate\nlayers: []\n";
    assert!(document::Packet::parse(duplicate, document::Format::Yaml, duplicate.len(),).is_err());
}
