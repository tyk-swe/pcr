// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::fmt;

use super::field::FieldValue;
use super::layer::{Id as ProtocolId, Layer};

mod boundary;
mod equality;
mod error;

pub use error::Error;

/// Exactly one ordered, arbitrary wire stack.
///
/// Cached encoded payload lengths are invalidated by every public operation
/// that can change the layers or a layer's fields.
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

    pub(crate) fn set_encoded_payload_lengths(
        &mut self,
        encoded_payload_lengths: Vec<Option<usize>>,
    ) {
        debug_assert_eq!(encoded_payload_lengths.len(), self.layers.len());
        self.encoded_payload_lengths = encoded_payload_lengths;
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
        self.push_boxed(Box::new(layer))
    }

    pub fn push_boxed(&mut self, layer: Box<dyn Layer>) -> &mut Self {
        self.layers.push(layer);
        self.invalidate_encoded_payload_lengths();
        self
    }

    pub fn insert<L>(&mut self, index: usize, layer: L) -> Result<&mut Self, Error>
    where
        L: Layer + 'static,
    {
        self.insert_boxed(index, Box::new(layer))
    }

    pub fn insert_boxed(
        &mut self,
        index: usize,
        layer: Box<dyn Layer>,
    ) -> Result<&mut Self, Error> {
        if index > self.layers.len() {
            return Err(Error::IndexOutOfBounds {
                index,
                len: self.layers.len(),
            });
        }
        boundary::shift_padding_for_insert(&mut self.layers, index);
        self.layers.insert(index, layer);
        self.invalidate_encoded_payload_lengths();
        Ok(self)
    }

    pub fn remove(&mut self, index: usize) -> Result<Box<dyn Layer>, Error> {
        if index >= self.layers.len() {
            return Err(Error::IndexOutOfBounds {
                index,
                len: self.layers.len(),
            });
        }
        if boundary::check_padding_boundary_removal(&self.layers, index) {
            return Err(Error::PaddingBoundaryRemoval { index });
        }
        let removed = self.layers.remove(index);
        boundary::shift_padding_for_remove(&mut self.layers, index);
        self.invalidate_encoded_payload_lengths();
        Ok(removed)
    }

    pub fn replace<L>(&mut self, index: usize, layer: L) -> Result<Box<dyn Layer>, Error>
    where
        L: Layer + 'static,
    {
        self.replace_boxed(index, Box::new(layer))
    }

    pub fn replace_boxed(
        &mut self,
        index: usize,
        mut layer: Box<dyn Layer>,
    ) -> Result<Box<dyn Layer>, Error> {
        let len = self.layers.len();
        let slot = self
            .layers
            .get_mut(index)
            .ok_or(Error::IndexOutOfBounds { index, len })?;
        std::mem::swap(slot, &mut layer);
        self.invalidate_encoded_payload_lengths();
        Ok(layer)
    }

    pub fn get<T: Layer + 'static>(&self) -> Option<&T> {
        self.layers
            .iter()
            .find_map(|layer| layer.as_any().downcast_ref::<T>())
    }

    /// Returns the first layer of type `T` for mutation.
    ///
    /// Obtaining mutable layer access invalidates cached encoded payload
    /// lengths before the reference is returned. A failed type lookup does
    /// not change the packet.
    pub fn get_mut<T: Layer + 'static>(&mut self) -> Option<&mut T> {
        let index = self
            .layers
            .iter()
            .position(|layer| layer.as_any().is::<T>())?;
        self.invalidate_encoded_payload_lengths();
        self.layers[index].as_any_mut().downcast_mut::<T>()
    }

    pub fn get_all<T: Layer + 'static>(&self) -> impl Iterator<Item = &T> {
        self.layers
            .iter()
            .filter_map(|layer| layer.as_any().downcast_ref::<T>())
    }

    pub fn by_protocol(&self, protocol: &ProtocolId) -> Option<&dyn Layer> {
        self.layers
            .iter()
            .map(Box::as_ref)
            .find(|layer| layer.protocol_id() == protocol)
    }

    /// Returns the first layer with `protocol` for mutation.
    ///
    /// Obtaining mutable layer access invalidates cached encoded payload
    /// lengths before the reference is returned. A failed protocol lookup
    /// does not change the packet.
    pub fn by_protocol_mut(&mut self, protocol: &ProtocolId) -> Option<&mut dyn Layer> {
        let index = self
            .layers
            .iter()
            .position(|layer| layer.protocol_id() == protocol)?;
        self.invalidate_encoded_payload_lengths();
        Some(self.layers[index].as_mut())
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

    /// Returns a layer at `index` for mutation.
    ///
    /// Obtaining mutable layer access invalidates cached encoded payload
    /// lengths before the reference is returned. An out-of-bounds index does
    /// not change the packet.
    pub fn layer_mut(&mut self, index: usize) -> Option<&mut dyn Layer> {
        if index >= self.layers.len() {
            return None;
        }
        self.invalidate_encoded_payload_lengths();
        Some(self.layers[index].as_mut())
    }

    pub fn iter(&self) -> impl ExactSizeIterator<Item = &dyn Layer> + DoubleEndedIterator {
        self.layers.iter().map(Box::as_ref)
    }

    /// Edits a reflected field, invalidating cached encoded payload lengths
    /// before the field mutation is attempted.
    pub fn edit(
        &mut self,
        protocol: &ProtocolId,
        field: &str,
        value: FieldValue,
    ) -> Result<(), Error> {
        let layer = self
            .by_protocol_mut(protocol)
            .ok_or_else(|| Error::ProtocolNotFound {
                protocol: protocol.clone(),
            })?;
        layer.set_field(field, value)?;
        Ok(())
    }

    /// Compares protocol order and every reflected field.
    pub fn structurally_eq(&self, other: &Self) -> bool {
        equality::structurally_eq(self, other)
    }

    /// Returns the cached number of encoded bytes after the layer at `index`.
    ///
    /// The value includes trailing padding and is available only for packets
    /// produced by the decoder or builder without subsequent mutable access.
    pub fn encoded_payload_length(&self, index: usize) -> Option<usize> {
        self.encoded_payload_lengths.get(index).copied().flatten()
    }

    fn invalidate_encoded_payload_lengths(&mut self) {
        self.encoded_payload_lengths.resize(self.layers.len(), None);
        self.encoded_payload_lengths.fill(None);
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
        let layers = iter
            .into_iter()
            .map(|layer| Box::new(layer) as Box<dyn Layer>)
            .collect::<Vec<_>>();
        let encoded_payload_lengths = vec![None; layers.len()];
        Self {
            layers,
            encoded_payload_lengths,
        }
    }
}
