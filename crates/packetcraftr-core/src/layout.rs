// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Byte-level packet layouts.

use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
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

    pub(crate) fn checked_shift(&mut self, amount: usize) -> bool {
        let (Some(start), Some(end)) =
            (self.start.checked_add(amount), self.end.checked_add(amount))
        else {
            return false;
        };
        self.start = start;
        self.end = end;
        true
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FieldLayout {
    pub name: String,
    pub range: ByteRange,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LayerLayout {
    pub index: usize,
    pub protocol: crate::layer::Id,
    pub range: ByteRange,
    pub fields: Vec<FieldLayout>,
}

impl LayerLayout {
    pub(crate) fn checked_shift(&mut self, amount: usize) -> bool {
        if self.range.start.checked_add(amount).is_none()
            || self.range.end.checked_add(amount).is_none()
            || self.fields.iter().any(|field| {
                field.range.start.checked_add(amount).is_none()
                    || field.range.end.checked_add(amount).is_none()
            })
        {
            return false;
        }
        let shifted = self.range.checked_shift(amount);
        debug_assert!(shifted);
        for field in &mut self.fields {
            let shifted = field.range.checked_shift(amount);
            debug_assert!(shifted);
        }
        true
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PacketLayout {
    pub layers: Vec<LayerLayout>,
}

impl PacketLayout {
    pub fn layer(&self, index: usize) -> Option<&LayerLayout> {
        self.layers.iter().find(|layout| layout.index == index)
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
                name: "value".to_owned(),
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
    fn packet_layout_lookup_uses_semantic_layer_indices() {
        let expected = layer();
        let layout = PacketLayout {
            layers: vec![expected.clone()],
        };

        assert_eq!(layout.layer(3), Some(&expected));
        assert_eq!(layout.layer(0), None);
    }
}
