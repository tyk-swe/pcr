// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Byte-level packet layouts.

use serde::Serialize;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub struct ByteRange {
    pub start: usize,
    pub end: usize,
}

impl ByteRange {
    pub fn new(start: usize, end: usize) -> Self {
        Self { start, end }
    }

    pub(crate) fn len(self) -> usize {
        self.end.saturating_sub(self.start)
    }

    pub(crate) fn shifted(self, amount: usize) -> Option<Self> {
        Some(Self {
            start: self.start.checked_add(amount)?,
            end: self.end.checked_add(amount)?,
        })
    }

    pub(crate) fn checked_shift(&mut self, amount: usize) -> bool {
        match self.shifted(amount) {
            Some(shifted) => {
                *self = shifted;
                true
            }
            None => false,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct FieldLayout {
    pub name: &'static str,
    pub range: ByteRange,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct LayerLayout {
    pub index: usize,
    pub protocol: crate::layer::Id,
    pub range: ByteRange,
    pub fields: Vec<FieldLayout>,
}

impl LayerLayout {
    pub(crate) fn checked_shift(&mut self, amount: usize) -> bool {
        let Some(range) = self.range.shifted(amount) else {
            return false;
        };
        let Some(fields) = self
            .fields
            .iter()
            .map(|field| {
                Some(FieldLayout {
                    name: field.name,
                    range: field.range.shifted(amount)?,
                })
            })
            .collect::<Option<Vec<_>>>()
        else {
            return false;
        };
        self.range = range;
        self.fields = fields;
        true
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct PacketLayout {
    pub layers: Vec<LayerLayout>,
}

impl PacketLayout {
    /// Every producer appends one layout per layer it pushes, so `layers[position].index == position`.
    #[must_use]
    pub fn new(layers: Vec<LayerLayout>) -> Self {
        debug_assert!(
            layers
                .iter()
                .enumerate()
                .all(|(position, layout)| layout.index == position),
            "packet layout layers must be stored at their own semantic index"
        );
        Self { layers }
    }

    pub fn layer(&self, index: usize) -> Option<&LayerLayout> {
        self.layers
            .get(index)
            .filter(|layout| layout.index == index)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::layer::Id;

    fn layer() -> LayerLayout {
        LayerLayout {
            index: 3,
            protocol: Id::new("fixture"),
            range: ByteRange::new(2, 8),
            fields: vec![FieldLayout {
                name: "value",
                range: ByteRange::new(4, 6),
            }],
        }
    }

    #[test]
    fn byte_range_length_saturates_and_failed_shift_is_atomic() {
        assert_eq!(ByteRange::new(2, 8).len(), 6);
        assert_eq!(ByteRange::new(8, 2).len(), 0);

        let mut range = ByteRange::new(usize::MAX - 1, usize::MAX);
        assert!(!range.checked_shift(1));
        assert_eq!(range, ByteRange::new(usize::MAX - 1, usize::MAX));
    }

    #[test]
    fn layer_shift_updates_every_range_or_none_of_them() {
        let mut shifted = layer();
        assert!(shifted.checked_shift(10));
        assert_eq!(shifted.range, ByteRange::new(12, 18));
        assert_eq!(shifted.fields[0].range, ByteRange::new(14, 16));

        let mut overflowing = layer();
        overflowing.fields[0].range.end = usize::MAX;
        let before = overflowing.clone();
        assert!(!overflowing.checked_shift(1));
        assert_eq!(overflowing, before);
    }

    #[test]
    fn packet_layout_lookup_is_positional_and_rejects_a_disagreeing_index() {
        let mut expected = layer();
        expected.index = 0;
        let layout = PacketLayout::new(vec![expected.clone()]);

        assert_eq!(layout.layer(0), Some(&expected));
        assert_eq!(layout.layer(1), None);

        let inconsistent = PacketLayout {
            layers: vec![layer()],
        };
        assert_eq!(inconsistent.layer(0), None);
        assert_eq!(inconsistent.layer(3), None);
    }
}
