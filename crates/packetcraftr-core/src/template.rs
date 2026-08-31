// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Bounded packet templates.

use thiserror::Error;

use crate::Packet;
use crate::field::FieldValue;
use crate::layer::FieldError;

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
    axis: Option<TemplateAxis>,
}

impl Template {
    pub fn new(base: Packet) -> Self {
        Self { base, axis: None }
    }

    /// Sets the single field the template varies, replacing any earlier axis.
    #[must_use]
    pub fn axis(mut self, layer: usize, field: impl Into<String>, values: Vec<FieldValue>) -> Self {
        self.axis = Some(TemplateAxis {
            layer,
            field: field.into(),
            values,
        });
        self
    }

    /// Number of packets this template expands to: one per axis value, or one
    /// packet when no axis is set.
    #[must_use]
    pub fn expansion_len(&self) -> usize {
        self.axis.as_ref().map_or(1, |axis| axis.values.len())
    }

    pub fn expand(
        &self,
        maximum: usize,
    ) -> Result<impl ExactSizeIterator<Item = Result<Packet, Error>> + '_, Error> {
        let total = self.expansion_len();
        if total > maximum {
            return Err(Error::ExpansionLimit {
                requested: total,
                limit: maximum,
            });
        }
        Ok((0..total).map(move |ordinal| {
            let mut packet = self.base.clone();
            // Absent only when the template varies nothing, which expands to
            // the base packet alone.
            let Some((axis, value)) = self
                .axis
                .as_ref()
                .and_then(|axis| Some((axis, axis.values.get(ordinal)?)))
            else {
                return Ok(packet);
            };
            let packet_len = packet.len();
            let layer = packet.layer_mut(axis.layer).ok_or(Error::LayerIndex {
                index: axis.layer,
                len: packet_len,
            })?;
            layer
                .set_field(&axis.field, value.clone())
                .map_err(|source| Error::Field {
                    layer: axis.layer,
                    field: axis.field.clone(),
                    source,
                })?;
            Ok(packet)
        }))
    }
}

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
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
