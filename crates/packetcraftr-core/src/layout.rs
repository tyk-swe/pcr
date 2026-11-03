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
    pub index: usize,
    pub range: ByteRange,
}

impl FieldLayout {
    pub fn name(&self, schema: &crate::layer::Schema) -> Option<&'static str> {
        schema.fields.get(self.index).map(|field| field.name)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct LayerLayout {
    pub index: usize,
    pub protocol: crate::layer::Id,
    #[serde(skip)]
    pub schema: &'static crate::layer::Schema,
    pub range: ByteRange,
    pub fields: Vec<FieldLayout>,
}

impl LayerLayout {
    /// Shifts the layer and its fields together, or leaves both unchanged.
    pub(crate) fn checked_shift(&mut self, amount: usize) -> bool {
        let Some(range) = self.range.shifted(amount) else {
            return false;
        };
        if !self
            .fields
            .iter()
            .all(|field| field.range.shifted(amount).is_some())
        {
            return false;
        }
        self.range = range;
        for field in &mut self.fields {
            field.range.checked_shift(amount);
        }
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

    fn layout() -> LayerLayout {
        static SCHEMA: crate::layer::Schema = crate::layer::Schema {
            protocol: crate::layer::Id::new("test"),
            name: "Test",
            fields: &[],
        };
        LayerLayout {
            index: 0,
            protocol: crate::layer::Id::new("test"),
            schema: &SCHEMA,
            range: ByteRange::new(2, 6),
            fields: vec![FieldLayout {
                index: 0,
                range: ByteRange::new(2, 4),
            }],
        }
    }

    #[test]
    fn byte_range_len_is_end_minus_start() {
        assert_eq!(ByteRange::new(2, 6).len(), 4);
        assert_eq!(ByteRange::new(6, 6).len(), 0);
        assert_eq!(ByteRange::new(6, 2).len(), 0);
    }

    #[test]
    fn checked_shift_moves_layer_and_fields_together() {
        let mut layout = layout();
        assert!(layout.checked_shift(3));
        assert_eq!(layout.range, ByteRange::new(5, 9));
        assert_eq!(layout.fields[0].range, ByteRange::new(5, 7));
    }

    #[test]
    fn checked_shift_overflow_leaves_layout_unchanged() {
        let mut layout = layout();
        assert!(!layout.checked_shift(usize::MAX));
        assert_eq!(layout.range, ByteRange::new(2, 6));
        assert_eq!(layout.fields[0].range, ByteRange::new(2, 4));
    }
}
