// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::fmt;

use super::layer::Layer;

mod boundary;
mod error;

pub use error::PacketError;

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

    pub fn push<L: Layer>(&mut self, layer: L) -> &mut Self {
        self.push_boxed(Box::new(layer))
    }

    pub fn push_boxed(&mut self, layer: Box<dyn Layer>) -> &mut Self {
        self.layers.push(layer);
        self.invalidate_encoded_payload_lengths();
        self
    }

    pub fn insert<L: Layer>(&mut self, index: usize, layer: L) -> Result<&mut Self, PacketError> {
        if index > self.layers.len() {
            return Err(PacketError::IndexOutOfBounds {
                index,
                len: self.layers.len(),
            });
        }
        boundary::shift_padding_for_insert(&mut self.layers, index);
        self.layers.insert(index, Box::new(layer));
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
        if boundary::removal_would_orphan_padding(&self.layers, index) {
            return Err(PacketError::PaddingBoundaryRemoval { index });
        }
        let removed = self.layers.remove(index);
        boundary::shift_padding_for_remove(&mut self.layers, index);
        self.invalidate_encoded_payload_lengths();
        Ok(removed)
    }

    pub fn replace<L: Layer>(
        &mut self,
        index: usize,
        layer: L,
    ) -> Result<Box<dyn Layer>, PacketError> {
        let mut layer: Box<dyn Layer> = Box::new(layer);
        let len = self.layers.len();
        let slot = self
            .layers
            .get_mut(index)
            .ok_or(PacketError::IndexOutOfBounds { index, len })?;
        std::mem::swap(slot, &mut layer);
        self.invalidate_encoded_payload_lengths();
        Ok(layer)
    }

    pub fn get<T: Layer>(&self) -> Option<&T> {
        self.layers
            .iter()
            .find_map(|layer| layer.as_any().downcast_ref::<T>())
    }

    /// Returns the first layer of type `T` for mutation.
    ///
    /// Obtaining mutable layer access invalidates cached encoded payload
    /// lengths before the reference is returned. A failed type lookup does
    /// not change the packet.
    pub fn get_mut<T: Layer>(&mut self) -> Option<&mut T> {
        let index = self
            .layers
            .iter()
            .position(|layer| layer.as_any().is::<T>())?;
        self.invalidate_encoded_payload_lengths();
        self.layers.get_mut(index)?.as_any_mut().downcast_mut::<T>()
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
        Some(self.layers.get_mut(index)?.as_mut())
    }

    pub fn iter(&self) -> impl ExactSizeIterator<Item = &dyn Layer> + DoubleEndedIterator {
        self.layers.iter().map(Box::as_ref)
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

impl<L: Layer> FromIterator<L> for Packet {
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
