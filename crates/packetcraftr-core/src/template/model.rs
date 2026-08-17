// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use thiserror::Error;

use super::super::Packet;
use super::super::field::FieldValue;
use super::super::layer::FieldError;

pub const DEFAULT_MAX_TEMPLATE_PACKETS: usize = 10_000;

#[derive(Clone, Debug)]
struct TemplateAxis {
    layer: usize,
    field: String,
    values: Vec<FieldValue>,
}

#[derive(Clone, Debug)]
pub struct Template {
    base: Packet,
    axes: Vec<TemplateAxis>,
}

impl Template {
    pub fn new(base: Packet) -> Self {
        Self {
            base,
            axes: Vec::new(),
        }
    }

    #[must_use]
    pub fn axis(mut self, layer: usize, field: impl Into<String>, values: Vec<FieldValue>) -> Self {
        self.axes.push(TemplateAxis {
            layer,
            field: field.into(),
            values,
        });
        self
    }

    pub fn expansion_len(&self) -> Result<usize, Error> {
        if self.axes.is_empty() {
            return Ok(1);
        }
        self.axes.iter().try_fold(1usize, |product, axis| {
            product
                .checked_mul(axis.values.len())
                .ok_or(Error::ExpansionOverflow)
        })
    }

    pub fn expand(&self, maximum: usize) -> Result<Iter<'_>, Error> {
        let total = self.expansion_len()?;
        if total > maximum {
            return Err(Error::ExpansionLimit {
                requested: total,
                limit: maximum,
            });
        }
        Ok(Iter {
            template: self,
            next_ordinal: 0,
            total,
        })
    }
}

pub struct Iter<'a> {
    template: &'a Template,
    next_ordinal: usize,
    total: usize,
}

impl Iterator for Iter<'_> {
    type Item = Result<Packet, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.next_ordinal >= self.total {
            return None;
        }
        let ordinal = self.next_ordinal;
        self.next_ordinal += 1;
        let mut packet = self.template.base.clone();
        let mut divisor = self.total;
        for axis in &self.template.axes {
            let length = axis.values.len();
            if length == 0 {
                return None;
            }
            divisor /= length;
            let index = (ordinal / divisor) % length;
            let value = axis.values[index].clone();
            let Some(layer) = packet.layer_mut(axis.layer) else {
                return Some(Err(Error::LayerIndex {
                    index: axis.layer,
                    len: packet.len(),
                }));
            };
            if let Err(source) = layer.set_field(&axis.field, value) {
                return Some(Err(Error::Field {
                    layer: axis.layer,
                    field: axis.field.clone(),
                    source,
                }));
            }
        }
        Some(Ok(packet))
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self.total.saturating_sub(self.next_ordinal);
        (remaining, Some(remaining))
    }
}

impl ExactSizeIterator for Iter<'_> {}

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    #[error("template expansion arithmetic overflow")]
    ExpansionOverflow,
    #[error("template expands to {requested} packets, exceeding limit {limit}")]
    ExpansionLimit { requested: usize, limit: usize },
    #[error("template layer index {index} is outside packet length {len}")]
    LayerIndex { index: usize, len: usize },
    #[error("could not set template field {field} on layer {layer}: {source}")]
    Field {
        layer: usize,
        field: String,
        #[source]
        source: FieldError,
    },
}
