// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::fmt;

use thiserror::Error;

use super::field::FieldValue;
use super::layer::{FieldError, Layer, Padding, ProtocolId};

#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum PacketError {
    #[error("layer index {index} is outside packet length {len}")]
    IndexOutOfBounds { index: usize, len: usize },
    #[error("packet has no layer with protocol id {protocol}")]
    ProtocolNotFound { protocol: ProtocolId },
    #[error(
        "cannot remove layer {index}: padding coverage ends at that layer and no successor can preserve the boundary"
    )]
    PaddingBoundaryRemoval { index: usize },
    #[error(transparent)]
    Field(#[from] FieldError),
}

/// Exactly one ordered, arbitrary wire stack.
#[derive(Clone, Default)]
pub struct Packet {
    layers: Vec<Box<dyn Layer>>,
    encoded_payload_lengths: Vec<Option<usize>>,
}

impl Packet {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            layers: Vec::with_capacity(capacity),
            encoded_payload_lengths: Vec::with_capacity(capacity),
        }
    }

    pub fn from_layers(layers: Vec<Box<dyn Layer>>) -> Self {
        let encoded_payload_lengths = vec![None; layers.len()];
        Self {
            layers,
            encoded_payload_lengths,
        }
    }

    pub fn len(&self) -> usize {
        self.layers.len()
    }

    pub fn is_empty(&self) -> bool {
        self.layers.is_empty()
    }

    pub fn push<L>(&mut self, layer: L) -> &mut Self
    where
        L: Layer + 'static,
    {
        self.layers.push(Box::new(layer));
        self.invalidate_encoded_payload_lengths();
        self
    }

    pub fn push_boxed(&mut self, layer: Box<dyn Layer>) -> &mut Self {
        self.layers.push(layer);
        self.invalidate_encoded_payload_lengths();
        self
    }

    pub fn insert<L>(&mut self, index: usize, layer: L) -> Result<&mut Self, PacketError>
    where
        L: Layer + 'static,
    {
        self.insert_boxed(index, Box::new(layer))
    }

    pub fn insert_boxed(
        &mut self,
        index: usize,
        layer: Box<dyn Layer>,
    ) -> Result<&mut Self, PacketError> {
        if index > self.layers.len() {
            return Err(PacketError::IndexOutOfBounds {
                index,
                len: self.layers.len(),
            });
        }
        self.shift_padding_for_insert(index);
        self.layers.insert(index, layer);
        self.invalidate_encoded_payload_lengths();
        Ok(self)
    }

    pub fn remove(&mut self, index: usize) -> Result<Box<dyn Layer>, PacketError> {
        if index >= self.layers.len() {
            return Err(PacketError::IndexOutOfBounds {
                index,
                len: self.layers.len(),
            });
        }
        let loses_exact_padding_boundary =
            self.layers
                .iter()
                .enumerate()
                .any(|(padding_index, layer)| {
                    layer
                        .as_any()
                        .downcast_ref::<Padding>()
                        .is_some_and(|padding| {
                            padding.outside_layer == Some(index) && index + 1 >= padding_index
                        })
                });
        if loses_exact_padding_boundary {
            return Err(PacketError::PaddingBoundaryRemoval { index });
        }
        let removed = self.layers.remove(index);
        self.shift_padding_for_remove(index);
        self.invalidate_encoded_payload_lengths();
        Ok(removed)
    }

    pub fn replace<L>(&mut self, index: usize, layer: L) -> Result<Box<dyn Layer>, PacketError>
    where
        L: Layer + 'static,
    {
        self.replace_boxed(index, Box::new(layer))
    }

    pub fn replace_boxed(
        &mut self,
        index: usize,
        mut layer: Box<dyn Layer>,
    ) -> Result<Box<dyn Layer>, PacketError> {
        let len = self.layers.len();
        let slot = self
            .layers
            .get_mut(index)
            .ok_or(PacketError::IndexOutOfBounds { index, len })?;
        std::mem::swap(slot, &mut layer);
        self.invalidate_encoded_payload_lengths();
        Ok(layer)
    }

    pub fn get<T: Layer + 'static>(&self) -> Option<&T> {
        self.layers
            .iter()
            .find_map(|layer| layer.as_any().downcast_ref::<T>())
    }

    pub fn get_mut<T: Layer + 'static>(&mut self) -> Option<&mut T> {
        self.invalidate_encoded_payload_lengths();
        self.layers
            .iter_mut()
            .find_map(|layer| layer.as_any_mut().downcast_mut::<T>())
    }

    pub fn get_all<T: Layer + 'static>(&self) -> impl Iterator<Item = &T> {
        self.layers
            .iter()
            .filter_map(|layer| layer.as_any().downcast_ref::<T>())
    }

    pub fn get_all_mut<T: Layer + 'static>(&mut self) -> impl Iterator<Item = &mut T> {
        self.invalidate_encoded_payload_lengths();
        self.layers
            .iter_mut()
            .filter_map(|layer| layer.as_any_mut().downcast_mut::<T>())
    }

    pub fn by_protocol(&self, protocol: &ProtocolId) -> Option<&dyn Layer> {
        for layer in &self.layers {
            if &layer.protocol_id() == protocol {
                return Some(layer.as_ref());
            }
        }
        None
    }

    pub fn by_protocol_mut(&mut self, protocol: &ProtocolId) -> Option<&mut dyn Layer> {
        self.invalidate_encoded_payload_lengths();
        for layer in &mut self.layers {
            if &layer.protocol_id() == protocol {
                return Some(layer.as_mut());
            }
        }
        None
    }

    pub fn all_by_protocol<'a>(
        &'a self,
        protocol: &'a ProtocolId,
    ) -> impl Iterator<Item = &'a dyn Layer> + 'a {
        self.layers
            .iter()
            .filter_map(move |layer| (&layer.protocol_id() == protocol).then_some(layer.as_ref()))
    }

    pub fn layer(&self, index: usize) -> Option<&dyn Layer> {
        self.layers.get(index).map(Box::as_ref)
    }

    pub fn layer_mut(&mut self, index: usize) -> Option<&mut dyn Layer> {
        self.invalidate_encoded_payload_lengths();
        match self.layers.get_mut(index) {
            Some(layer) => Some(layer.as_mut()),
            None => None,
        }
    }

    pub fn iter(&self) -> impl ExactSizeIterator<Item = &dyn Layer> + DoubleEndedIterator {
        self.layers.iter().map(Box::as_ref)
    }

    pub fn edit(
        &mut self,
        protocol: &ProtocolId,
        field: &str,
        value: FieldValue,
    ) -> Result<(), PacketError> {
        self.invalidate_encoded_payload_lengths();
        let layer =
            self.by_protocol_mut(protocol)
                .ok_or_else(|| PacketError::ProtocolNotFound {
                    protocol: protocol.clone(),
                })?;
        layer.set_field(field, value)?;
        Ok(())
    }

    pub fn normalize(&mut self) {
        self.invalidate_encoded_payload_lengths();
        for layer in &mut self.layers {
            layer.normalize();
        }
    }

    /// Compares protocol order and every reflected field.
    pub fn structurally_eq(&self, other: &Self) -> bool {
        if self.len() != other.len() {
            return false;
        }
        self.iter().zip(other.iter()).all(|(left, right)| {
            if left.protocol_id() != right.protocol_id() {
                return false;
            }
            if left.schema() != right.schema() {
                return false;
            }
            left.schema()
                .fields
                .iter()
                .all(|field| left.field(field.name) == right.field(field.name))
        })
    }

    pub(crate) fn encoded_payload_length(&self, index: usize) -> Option<usize> {
        self.encoded_payload_lengths.get(index).copied().flatten()
    }

    pub(crate) fn set_encoded_payload_lengths(&mut self, lengths: Vec<Option<usize>>) {
        debug_assert_eq!(lengths.len(), self.layers.len());
        self.encoded_payload_lengths = lengths;
    }

    fn invalidate_encoded_payload_lengths(&mut self) {
        self.encoded_payload_lengths.clear();
        self.encoded_payload_lengths.resize(self.layers.len(), None);
    }

    fn shift_padding_for_insert(&mut self, index: usize) {
        for layer in &mut self.layers {
            let Some(padding) = layer.as_any_mut().downcast_mut::<Padding>() else {
                continue;
            };
            if let Some(outside_layer) = &mut padding.outside_layer {
                if *outside_layer >= index {
                    *outside_layer = outside_layer.saturating_add(1);
                }
            }
        }
    }

    fn shift_padding_for_remove(&mut self, index: usize) {
        for layer in &mut self.layers {
            let Some(padding) = layer.as_any_mut().downcast_mut::<Padding>() else {
                continue;
            };
            padding.outside_layer = match padding.outside_layer {
                Some(outside_layer) if outside_layer > index => Some(outside_layer - 1),
                // The successor shifts into the removed layer's index and
                // remains the first layer that excludes this padding.
                Some(outside_layer) if outside_layer == index => Some(index),
                value => value,
            };
        }
    }
}

impl fmt::Debug for Packet {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut list = formatter.debug_list();
        for layer in &self.layers {
            list.entry(layer);
        }
        list.finish()
    }
}

impl<L> FromIterator<L> for Packet
where
    L: Layer + 'static,
{
    fn from_iter<T: IntoIterator<Item = L>>(iter: T) -> Self {
        let mut packet = Self::new();
        for layer in iter {
            packet.push(layer);
        }
        packet
    }
}

#[cfg(test)]
mod tests {
    use std::any::Any;
    use std::sync::OnceLock;

    use bytes::Bytes;

    use super::*;
    use crate::packet::layer::{FieldSchema, LayerSchema, Padding, Raw};

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
                protocol: self.protocol_id(),
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
}
