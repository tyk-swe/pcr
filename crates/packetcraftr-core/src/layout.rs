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
