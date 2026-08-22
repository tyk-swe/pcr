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

    pub fn expand(
        &self,
        maximum: usize,
    ) -> Result<impl ExactSizeIterator<Item = Result<Packet, Error>> + '_, Error> {
        let total = self.expansion_len()?;
        if total > maximum {
            return Err(Error::ExpansionLimit {
                requested: total,
                limit: maximum,
            });
        }
        Ok((0..total).map(move |ordinal| {
            let mut packet = self.base.clone();
            let mut divisor = total;
            for axis in &self.axes {
                let length = axis.values.len();
                divisor /= length;
                let index = (ordinal / divisor) % length;
                let value = axis.values[index].clone();
                let packet_len = packet.len();
                let layer = packet.layer_mut(axis.layer).ok_or(Error::LayerIndex {
                    index: axis.layer,
                    len: packet_len,
                })?;
                layer
                    .set_field(&axis.field, value)
                    .map_err(|source| Error::Field {
                        layer: axis.layer,
                        field: axis.field.clone(),
                        source,
                    })?;
            }
            Ok(packet)
        }))
    }
}

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
