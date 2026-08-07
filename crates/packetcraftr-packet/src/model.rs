// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::fmt;

use super::field::FieldValue;
use super::layer::{Layer, ProtocolId};

mod boundary;
mod equality;
mod error;

pub use error::PacketError;

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

    pub(crate) fn from_encoded_layers(
        layers: Vec<Box<dyn Layer>>,
        encoded_payload_lengths: Vec<Option<usize>>,
    ) -> Self {
        debug_assert_eq!(encoded_payload_lengths.len(), layers.len());
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
        boundary::shift_padding_for_insert(&mut self.layers, index);
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
        if boundary::check_padding_boundary_removal(&self.layers, index) {
            return Err(PacketError::PaddingBoundaryRemoval { index });
        }
        let removed = self.layers.remove(index);
        boundary::shift_padding_for_remove(&mut self.layers, index);
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

    pub fn by_protocol(&self, protocol: &ProtocolId) -> Option<&dyn Layer> {
        for layer in &self.layers {
            if layer.protocol_id() == protocol {
                return Some(layer.as_ref());
            }
        }
        None
    }

    pub fn by_protocol_mut(&mut self, protocol: &ProtocolId) -> Option<&mut dyn Layer> {
        self.invalidate_encoded_payload_lengths();
        for layer in &mut self.layers {
            if layer.protocol_id() == protocol {
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
            .filter_map(move |layer| (layer.protocol_id() == protocol).then_some(layer.as_ref()))
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

    /// Mutates a layer whose encoded payload boundary is known to be unchanged.
    /// Callers must update only fixed-width fields covered by an existing layout.
    pub fn mutate_fixed_width_layer<T: Layer + 'static>(
        &mut self,
        index: usize,
        mutate: impl FnOnce(&mut T),
    ) -> bool {
        let Some(layer) = self.layers.get_mut(index) else {
            return false;
        };
        let Some(layer) = layer.as_any_mut().downcast_mut::<T>() else {
            return false;
        };
        mutate(layer);
        true
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
        let layer =
            self.by_protocol_mut(protocol)
                .ok_or_else(|| PacketError::ProtocolNotFound {
                    protocol: protocol.clone(),
                })?;
        layer.set_field(field, value)?;
        Ok(())
    }

    /// Compares protocol order and every reflected field.
    pub fn structurally_eq(&self, other: &Self) -> bool {
        equality::structurally_eq(self, other)
    }

    pub fn encoded_payload_length(&self, index: usize) -> Option<usize> {
        self.encoded_payload_lengths.get(index).copied().flatten()
    }

    fn invalidate_encoded_payload_lengths(&mut self) {
        self.encoded_payload_lengths.clear();
        self.encoded_payload_lengths.resize(self.layers.len(), None);
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
