// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::any::Any;
use std::sync::OnceLock;

use bytes::Bytes;

use super::Packet;
use super::error::PacketError;
use crate::field::FieldValue;
use crate::layer::{FieldError, FieldSchema, Layer, LayerSchema, Padding, ProtocolId, Raw};

#[derive(Clone, Debug)]
struct EmptyRaw;

impl Layer for EmptyRaw {
    fn schema(&self) -> &'static LayerSchema {
        static SCHEMA: OnceLock<LayerSchema> = OnceLock::new();
        static FIELDS: &[FieldSchema] = &[];
        SCHEMA.get_or_init(|| LayerSchema {
            protocol: ProtocolId::new("raw"),
            name: "Alternate Raw",
            fields: FIELDS,
        })
    }

    fn clone_box(&self) -> Box<dyn Layer> {
        Box::new(self.clone())
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }

    fn field(&self, _name: &str) -> Option<FieldValue> {
        None
    }

    fn set_field(&mut self, name: &str, _value: FieldValue) -> Result<(), FieldError> {
        Err(FieldError::UnknownField {
            protocol: self.protocol_id().clone(),
            field: name.to_owned(),
        })
    }
}

#[test]
fn packet_supports_arbitrary_repeated_typed_layers() {
    let mut packet = Packet::new();
    packet
        .push(Raw::new(Bytes::from_static(b"a")))
        .push(Padding::new(Bytes::from_static(b"b")))
        .push(Raw::new(Bytes::from_static(b"c")));

    assert_eq!(packet.len(), 3);
    assert_eq!(packet.get_all::<Raw>().count(), 2);
    assert_eq!(
        packet.get::<Padding>().unwrap().bytes,
        Bytes::from_static(b"b")
    );

    let raw = ProtocolId::new("raw");
    assert_eq!(
        packet
            .by_protocol(&raw)
            .unwrap()
            .as_any()
            .downcast_ref::<Raw>()
            .unwrap()
            .bytes,
        Bytes::from_static(b"a")
    );
    packet
        .by_protocol_mut(&raw)
        .unwrap()
        .set_field("bytes", FieldValue::Bytes(Bytes::from_static(b"updated")))
        .unwrap();
    assert_eq!(
        packet
            .all_by_protocol(&raw)
            .map(|layer| { layer.as_any().downcast_ref::<Raw>().unwrap().bytes.clone() })
            .collect::<Vec<_>>(),
        vec![Bytes::from_static(b"updated"), Bytes::from_static(b"c")]
    );
}

#[test]
fn reflective_edit_and_clone_preserve_independent_values() {
    let mut packet = Packet::new();
    packet.push(Raw::new(Bytes::from_static(b"old")));
    let clone = packet.clone();

    packet
        .edit(
            &ProtocolId::new("raw"),
            "bytes",
            FieldValue::Bytes(Bytes::from_static(b"new")),
        )
        .unwrap();

    assert_eq!(
        packet.get::<Raw>().unwrap().bytes,
        Bytes::from_static(b"new")
    );
    assert_eq!(
        clone.get::<Raw>().unwrap().bytes,
        Bytes::from_static(b"old")
    );
}

#[test]
fn insert_and_remove_keep_padding_coverage_boundary_aligned() {
    let mut packet = Packet::new();
    packet
        .push(Raw::new(Bytes::from_static(b"payload")))
        .push(Padding::after_layer(Bytes::from_static(b"pad"), 0));

    packet
        .insert(0, Raw::new(Bytes::from_static(b"outer")))
        .unwrap();
    assert_eq!(packet.get::<Padding>().unwrap().outside_layer, Some(1));
    packet.remove(0).unwrap();
    assert_eq!(packet.get::<Padding>().unwrap().outside_layer, Some(0));
}

#[test]
fn removing_exact_padding_boundary_preserves_its_successor() {
    let mut packet = Packet::new();
    packet
        .push(Raw::new(Bytes::from_static(b"outer")))
        .push(Raw::new(Bytes::from_static(b"inner")))
        .push(Padding::after_layer(Bytes::from_static(b"pad"), 0));

    packet.remove(0).unwrap();
    assert_eq!(packet.get::<Padding>().unwrap().outside_layer, Some(0));
    assert!(matches!(
        packet.remove(0),
        Err(PacketError::PaddingBoundaryRemoval { index: 0 })
    ));
}

#[test]
fn structural_equality_requires_the_same_canonical_schema_in_both_directions() {
    let mut regular = Packet::new();
    regular.push(Raw::new(Bytes::new()));
    let mut alternate = Packet::new();
    alternate.push(EmptyRaw);

    assert!(!regular.structurally_eq(&alternate));
    assert!(!alternate.structurally_eq(&regular));
    assert!(regular.structurally_eq(&regular.clone()));
}
