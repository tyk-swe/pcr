// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
// Test code indexes fixtures and counts by hand; the fail-closed lints are
// for library paths.
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

//! Contracts for packet mutation, field reflection, and stable layer views.

mod common;

use bytes::Bytes;
use common::probe::{Child, Probe, probe_layout, structure};
use packetcraftr_core::Packet;
use packetcraftr_core::diagnostic::Diagnostic;
use packetcraftr_core::field::FieldValue;
use packetcraftr_core::layer::{
    FieldError, Layer, Malformed, Padding, Raw, malformed_layout, padding_layout, raw_layout,
};
use packetcraftr_core::layout::{ByteRange, FieldLayout};
use std::net::{Ipv4Addr, Ipv6Addr};

fn assert_failed_packet_mutations(packet: &mut Packet) {
    let before_failed_mutations = packet.clone();
    assert!(
        packet
            .layer_mut(0)
            .and_then(|layer| layer.as_any_mut().downcast_mut::<Probe>())
            .is_none()
    );
    assert!(packet.layer_mut(99).is_none());
    assert!(packet.get_mut::<Raw>().is_none());
    assert!(matches!(
        packet.replace(99, Child::default()),
        Err(packetcraftr_core::PacketError::IndexOutOfBounds { index: 99, len: 4 })
    ));
    assert_eq!(structure(packet), structure(&before_failed_mutations));
    assert_eq!(packet.get::<Child>().map(|child| child.value), Some(10));
}

#[test]
fn packet_mutation_reflection_and_boundaries_are_consistent() {
    let mut packet = Packet::with_capacity(4);
    assert!(packet.is_empty());
    packet.push(Probe::default()).push(Probe {
        value: 2,
        ..Probe::default()
    });
    assert_eq!(packet.len(), 2);
    assert_eq!(
        packet
            .iter()
            .filter(|layer| layer.as_any().is::<Probe>())
            .count(),
        2
    );
    assert_eq!(
        packet
            .iter()
            .filter(|layer| layer.protocol_id() == &packetcraftr_core::layer::Id::new("probe"))
            .count(),
        2
    );
    assert_eq!(
        packet
            .iter()
            .next_back()
            .and_then(|layer| layer.field("value")),
        Some(2_u8.into())
    );

    packet.push(Padding::after_layer(vec![0xaa], 1));
    packet
        .insert(0, Child::default())
        .expect("insertion should shift an existing padding boundary");
    assert_eq!(
        packet
            .get::<Padding>()
            .and_then(|padding| padding.outside_layer),
        Some(2)
    );
    assert!(matches!(
        packet.insert(9, Raw::default()),
        Err(packetcraftr_core::PacketError::IndexOutOfBounds { index: 9, len: 4 })
    ));

    let removed = packet
        .replace(0, Child { value: 9 })
        .expect("replace layer");
    assert_eq!(removed.protocol_id().as_str(), "child");
    packet
        .layer_mut(0)
        .and_then(|layer| layer.as_any_mut().downcast_mut::<Child>())
        .expect("child layer at index 0")
        .value = 10;
    assert_failed_packet_mutations(&mut packet);

    assert!(matches!(
        packet.remove(2),
        Err(packetcraftr_core::PacketError::PaddingBoundaryRemoval { index: 2 })
    ));
    packet.remove(3).expect("padding itself can be removed");
    assert_eq!(packet.len(), 3);
    assert!(matches!(
        packet.remove(8),
        Err(packetcraftr_core::PacketError::IndexOutOfBounds { index: 8, len: 3 })
    ));

    packet
        .get_mut::<Probe>()
        .expect("probe layer")
        .set_field("probe_value", 42_u8.into())
        .expect("edit reflected value");
    assert_eq!(
        packet
            .iter()
            .find(|layer| layer.protocol_id() == &packetcraftr_core::layer::Id::new("probe"))
            .and_then(|layer| layer.field("probe_value")),
        Some(42_u8.into())
    );
    let before_failed_edits = packet.clone();
    assert!(matches!(
        packet
            .get_mut::<Probe>()
            .expect("probe layer")
            .set_field("unknown", 1_u8.into()),
        Err(FieldError::UnknownField { .. })
    ));
    assert!(matches!(
        packet
            .get_mut::<Probe>()
            .expect("probe layer")
            .set_field("value", FieldValue::Unsigned(256)),
        Err(FieldError::OutOfRange { .. })
    ));
    assert_eq!(structure(&packet), structure(&before_failed_edits));

    let clone = packet.clone();
    assert_eq!(structure(&packet), structure(&clone));
    packet.get_mut::<Probe>().expect("probe layer").value = 43;
    assert_ne!(structure(&packet), structure(&clone));
    assert!(format!("{packet:?}").contains("Probe"));

    let collected: Packet = [Child { value: 1 }, Child { value: 2 }]
        .into_iter()
        .collect();
    assert_eq!(collected.len(), 2);
}

#[test]
fn reflected_fields_cover_supported_types_and_fail_closed() {
    let mut layer = Probe::default();
    layer.set_field("enabled", true.into()).expect("bool");
    layer.set_field("label", "renamed".into()).expect("text");
    layer
        .set_field("bytes", vec![1, 2, 3].into())
        .expect("bytes");
    layer
        .set_field("ipv4", "192.0.2.4".into())
        .expect("IPv4 text");
    layer
        .set_field("ipv6", "2001:db8::4".into())
        .expect("IPv6 text");
    layer
        .set_field("mac", "00-11-22-33-44-55".into())
        .expect("MAC text");
    layer
        .set_field("token", FieldValue::Bytes(Bytes::from_static(b"12345678")))
        .expect("eight-byte token");
    layer
        .set_field("wire", "AUTO".into())
        .expect("auto wire value");
    assert_eq!(
        layer.field("wire"),
        Some(FieldValue::Text("auto".to_owned()))
    );
    layer
        .set_field("wire", 65_535_u64.into())
        .expect("exact wire value");
    assert_eq!(layer.wire.exact(), Some(&65_535));
    layer
        .set_field("wire", FieldValue::Bytes(Bytes::from_static(b"raw")))
        .expect("raw wire value");

    assert!(matches!(
        layer.set_field("enabled", 1_u8.into()),
        Err(FieldError::WrongType {
            expected: "bool",
            ..
        })
    ));
    assert!(matches!(
        layer.set_field("ipv4", "not-an-address".into()),
        Err(FieldError::WrongType {
            expected: "ipv4",
            ..
        })
    ));
    assert!(matches!(
        layer.set_field("ipv6", false.into()),
        Err(FieldError::WrongType {
            expected: "ipv6",
            ..
        })
    ));
    assert!(matches!(
        layer.set_field("mac", "00:11:22".into()),
        Err(FieldError::WrongType {
            expected: "mac address",
            ..
        })
    ));
    assert!(matches!(
        layer.set_field("token", vec![1, 2].into()),
        Err(FieldError::WrongType {
            expected: "eight bytes",
            ..
        })
    ));
    assert!(matches!(
        layer.set_field("wire", "manual".into()),
        Err(FieldError::WrongType {
            expected: "unsigned, bytes, or 'auto'",
            ..
        })
    ));

    let schema = layer.schema();
    assert_eq!(schema.name, "Probe");
    assert_eq!(schema.fields.len(), 9);
    layer
        .validate_required_fields()
        .expect("all required getters produce values");
    assert_eq!(
        probe_layout(),
        vec![FieldLayout {
            name: "value",
            range: ByteRange::new(0, 1)
        }]
    );
    assert_eq!(raw_layout(3)[0].range, ByteRange::new(0, 3));
    assert_eq!(padding_layout(2)[0].range, ByteRange::new(0, 2));
    assert_eq!(malformed_layout(4)[0].range, ByteRange::new(0, 4));
}

#[test]
fn field_values_raw_layers_and_diagnostics_have_stable_views() {
    let values = [
        FieldValue::Bool(true),
        FieldValue::Unsigned(7),
        FieldValue::Signed(-3),
        FieldValue::Text("text".to_owned()),
        FieldValue::Bytes(Bytes::from_static(&[0xab, 0xcd])),
        FieldValue::Ipv4(Ipv4Addr::LOCALHOST),
        FieldValue::Ipv6(Ipv6Addr::LOCALHOST),
        FieldValue::Mac([0, 1, 2, 3, 4, 5]),
        FieldValue::List(vec![1_u8.into(), "two".into()]),
    ];
    let rendered = values.iter().map(ToString::to_string).collect::<Vec<_>>();
    assert_eq!(
        rendered,
        [
            "true",
            "7",
            "-3",
            "text",
            "abcd",
            "127.0.0.1",
            "::1",
            "00:01:02:03:04:05",
            "1,two"
        ]
    );
    assert_eq!(values[1].as_u64(), Some(7));
    assert_eq!(values[0].as_bool(), Some(true));
    assert_eq!(values[0].as_u64(), None);
    assert_eq!(values[1].as_bool(), None);
    let serialized = serde_json::to_string(&values[4]).expect("serialize bytes field");
    assert_eq!(
        serde_json::from_str::<FieldValue>(&serialized).expect("deserialize bytes field"),
        values[4]
    );

    let mut raw = Raw::new(vec![1, 2]);
    assert_eq!(raw.field("bytes"), Some(vec![1, 2].into()));
    raw.set_field("bytes", vec![3].into())
        .expect("edit raw bytes");
    let mut padding = Padding::new(vec![0, 0]);
    assert_eq!(padding.field("outside_layer"), None);
    padding
        .set_field("outside_layer", 4_u8.into())
        .expect("set boundary");
    assert_eq!(padding.outside_layer, Some(4));
    assert!(matches!(
        padding.set_field("outside_layer", false.into()),
        Err(FieldError::WrongType { .. })
    ));
    let mut malformed = Malformed::new(None, vec![0xff], "bad header");
    malformed
        .set_field("protocol", "ipv4".into())
        .expect("set intended protocol");
    malformed
        .set_field("reason", "truncated".into())
        .expect("set reason");
    assert_eq!(malformed.intended_protocol.as_deref(), Some("ipv4"));

    let mut diagnostics = Vec::new();
    packetcraftr_core::diagnostic::push_once(
        &mut diagnostics,
        Diagnostic::info("once", "first")
            .at_layer(2)
            .at_field("value"),
    );
    packetcraftr_core::diagnostic::push_once(
        &mut diagnostics,
        Diagnostic::error("once", "duplicate"),
    );
    packetcraftr_core::diagnostic::push_once(
        &mut diagnostics,
        Diagnostic::warning("other", "kept"),
    );
    assert_eq!(diagnostics.len(), 2);
    assert_eq!(
        diagnostics[0].severity,
        packetcraftr_core::diagnostic::Severity::Info
    );
    assert_eq!(diagnostics[0].layer, Some(2));
    assert_eq!(diagnostics[0].field, Some("value"));
    assert_eq!(
        diagnostics[1].severity,
        packetcraftr_core::diagnostic::Severity::Warning
    );
}
