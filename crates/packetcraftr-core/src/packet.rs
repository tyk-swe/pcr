// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::fmt;

use crate::layer::{Layer, Padding};

mod limits;
mod link;
pub use limits::{DEFAULT_MAX_LAYERS, DEFAULT_MAX_PACKET_SIZE, Limits};
pub use link::{MacAddress, VlanKind, VlanTag};

#[derive(Clone)]
struct Entry {
    layer: Box<dyn Layer>,
    encoded_payload_length: Option<usize>,
}

impl Entry {
    fn new(layer: Box<dyn Layer>) -> Self {
        Self {
            layer,
            encoded_payload_length: None,
        }
    }
}

#[derive(Clone, Default)]
pub struct Packet {
    layers: Vec<Entry>,
}

impl Packet {
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            layers: Vec::with_capacity(capacity),
        }
    }

    pub(crate) fn from_encoded_layers(entries: Vec<(Box<dyn Layer>, Option<usize>)>) -> Self {
        Self {
            layers: entries
                .into_iter()
                .map(|(layer, encoded_payload_length)| Entry {
                    layer,
                    encoded_payload_length,
                })
                .collect(),
        }
    }

    pub(crate) fn set_encoded_payload_lengths(
        &mut self,
        encoded_payload_lengths: Vec<Option<usize>>,
    ) {
        debug_assert_eq!(encoded_payload_lengths.len(), self.layers.len());
        for (entry, length) in self.layers.iter_mut().zip(encoded_payload_lengths) {
            entry.encoded_payload_length = length;
        }
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
        self.layers.push(Entry::new(layer));
        self.invalidate_encoded_payload_lengths();
        self
    }

    pub fn insert<L: Layer>(&mut self, index: usize, layer: L) -> Result<&mut Self, Error> {
        if index > self.layers.len() {
            return Err(Error::IndexOutOfBounds {
                index,
                len: self.layers.len(),
            });
        }
        shift_padding_for_insert(&mut self.layers, index);
        self.layers.insert(index, Entry::new(Box::new(layer)));
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
        if removal_would_orphan_padding(&self.layers, index) {
            return Err(Error::PaddingBoundaryRemoval { index });
        }
        let removed = self.layers.remove(index).layer;
        shift_padding_for_remove(&mut self.layers, index);
        self.invalidate_encoded_payload_lengths();
        Ok(removed)
    }

    pub fn replace<L: Layer>(&mut self, index: usize, layer: L) -> Result<Box<dyn Layer>, Error> {
        let mut layer: Box<dyn Layer> = Box::new(layer);
        let len = self.layers.len();
        let slot = self
            .layers
            .get_mut(index)
            .ok_or(Error::IndexOutOfBounds { index, len })?;
        std::mem::swap(&mut slot.layer, &mut layer);
        self.invalidate_encoded_payload_lengths();
        Ok(layer)
    }

    pub fn get<T: Layer>(&self) -> Option<&T> {
        self.layers
            .iter()
            .find_map(|entry| entry.layer.downcast_ref::<T>())
    }

    pub fn get_mut<T: Layer>(&mut self) -> Option<&mut T> {
        let index = self.layers.iter().position(|entry| entry.layer.is::<T>())?;
        self.invalidate_encoded_payload_lengths();
        self.layers.get_mut(index)?.layer.downcast_mut::<T>()
    }

    pub fn layer(&self, index: usize) -> Option<&dyn Layer> {
        self.layers.get(index).map(|entry| entry.layer.as_ref())
    }

    pub fn layer_mut(&mut self, index: usize) -> Option<&mut dyn Layer> {
        if index >= self.layers.len() {
            return None;
        }
        self.invalidate_encoded_payload_lengths();
        Some(self.layers.get_mut(index)?.layer.as_mut())
    }

    pub fn iter(&self) -> impl ExactSizeIterator<Item = &dyn Layer> + DoubleEndedIterator {
        self.layers.iter().map(|entry| entry.layer.as_ref())
    }

    pub fn iter_of<T: Layer>(&self) -> impl DoubleEndedIterator<Item = &T> {
        self.layers
            .iter()
            .filter_map(|entry| entry.layer.downcast_ref::<T>())
    }

    pub fn iter_of_mut<T: Layer>(&mut self) -> impl DoubleEndedIterator<Item = &mut T> {
        if self.layers.iter().any(|entry| entry.layer.is::<T>()) {
            self.invalidate_encoded_payload_lengths();
        }
        self.layers
            .iter_mut()
            .filter_map(|entry| entry.layer.downcast_mut::<T>())
    }

    /// The value includes trailing padding and is available only for packets
    /// produced by the decoder or builder without subsequent mutable access.
    pub fn encoded_payload_length(&self, index: usize) -> Option<usize> {
        self.layers
            .get(index)
            .and_then(|entry| entry.encoded_payload_length)
    }

    fn invalidate_encoded_payload_lengths(&mut self) {
        for entry in &mut self.layers {
            entry.encoded_payload_length = None;
        }
    }
}

impl fmt::Debug for Packet {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut list = formatter.debug_list();
        for entry in &self.layers {
            list.entry(&entry.layer);
        }
        list.finish()
    }
}

impl<L: Layer> FromIterator<L> for Packet {
    fn from_iter<T: IntoIterator<Item = L>>(iter: T) -> Self {
        Self {
            layers: iter
                .into_iter()
                .map(|layer| Entry::new(Box::new(layer)))
                .collect(),
        }
    }
}

impl<L: Layer> Extend<L> for Packet {
    fn extend<T: IntoIterator<Item = L>>(&mut self, iter: T) {
        self.layers
            .extend(iter.into_iter().map(|layer| Entry::new(Box::new(layer))));
        self.invalidate_encoded_payload_lengths();
    }
}

pub struct Iter<'a> {
    entries: std::slice::Iter<'a, Entry>,
}

impl<'a> Iterator for Iter<'a> {
    type Item = &'a dyn Layer;

    fn next(&mut self) -> Option<Self::Item> {
        self.entries.next().map(|entry| entry.layer.as_ref())
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.entries.size_hint()
    }
}

impl DoubleEndedIterator for Iter<'_> {
    fn next_back(&mut self) -> Option<Self::Item> {
        self.entries.next_back().map(|entry| entry.layer.as_ref())
    }
}

impl ExactSizeIterator for Iter<'_> {}

impl<'a> IntoIterator for &'a Packet {
    type Item = &'a dyn Layer;
    type IntoIter = Iter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        Iter {
            entries: self.layers.iter(),
        }
    }
}

#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    #[error("layer index {index} is outside packet length {len}")]
    IndexOutOfBounds { index: usize, len: usize },
    #[error(
        "cannot remove layer {index}: padding coverage ends at that layer and no successor can preserve the boundary"
    )]
    PaddingBoundaryRemoval { index: usize },
    #[error(
        "invalid hexadecimal MAC address; expected six two-digit bytes separated by ':' or '-'"
    )]
    InvalidMacAddress,
}

impl crate::error::Classified for Error {
    fn classification(&self) -> crate::error::Classification {
        use crate::error::{Classification, Kind};
        match self {
            Self::IndexOutOfBounds { .. } => Classification::new(
                crate::error::Code::CliLayerIndex,
                Kind::Usage,
                Some("address a layer index inside the packet"),
            ),
            Self::PaddingBoundaryRemoval { .. } => Classification::new(
                crate::error::Code::PacketPaddingBoundary,
                Kind::Packet,
                Some("remove the padding layer before the layer its boundary depends on"),
            ),
            Self::InvalidMacAddress => {
                Classification::new(crate::error::Code::CliError, Kind::Usage, None)
            }
        }
    }
}

fn removal_would_orphan_padding(layers: &[Entry], index: usize) -> bool {
    layers.iter().enumerate().any(|(padding_index, entry)| {
        Padding::from_layer(&*entry.layer).is_some_and(|padding| {
            padding.outside_layer == Some(index) && index.saturating_add(1) >= padding_index
        })
    })
}

fn shift_padding_for_insert(layers: &mut [Entry], index: usize) {
    for entry in layers {
        let Some(padding) = Padding::from_layer_mut(&mut *entry.layer) else {
            continue;
        };
        if let Some(outside_layer) = &mut padding.outside_layer
            && *outside_layer >= index
        {
            *outside_layer = outside_layer.saturating_add(1);
        }
    }
}

fn shift_padding_for_remove(layers: &mut [Entry], index: usize) {
    for entry in layers {
        let Some(padding) = Padding::from_layer_mut(&mut *entry.layer) else {
            continue;
        };
        if let Some(outside_layer) = &mut padding.outside_layer
            && *outside_layer > index
        {
            *outside_layer = outside_layer.saturating_sub(1);
        }
    }
}
