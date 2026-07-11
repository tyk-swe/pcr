// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use serde::{Deserialize, Serialize};

use super::layer::ProtocolId;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ByteRange {
    pub start: usize,
    pub end: usize,
}

impl ByteRange {
    pub fn new(start: usize, end: usize) -> Self {
        Self { start, end }
    }

    pub fn len(self) -> usize {
        self.end.saturating_sub(self.start)
    }

    pub fn is_empty(self) -> bool {
        self.start >= self.end
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
    pub protocol: ProtocolId,
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
