// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Bounded packet templates.

use std::collections::HashSet;
use thiserror::Error;

use crate::error::{Classification, Classified, Kind};
use crate::field::FieldValue;
use crate::layer::FieldError;
use crate::packet::Packet;

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

    /// Adds a varying field to the Cartesian product. Declaration order is
    /// stable, with the last axis varying fastest. Repeating a field (including
    /// an alias of it) is rejected by [`Self::expand`].
    #[must_use]
    pub fn axis(mut self, layer: usize, field: impl Into<String>, values: Vec<FieldValue>) -> Self {
        self.axes.push(TemplateAxis {
            layer,
            field: field.into(),
            values,
        });
        self
    }

    /// Checked size of the Cartesian product: one without axes, zero when
    /// any axis is empty. No packets are allocated while counting.
    pub fn expansion_len(&self) -> Result<usize, Error> {
        if self.axes.iter().any(|axis| axis.values.is_empty()) {
            return Ok(0);
        }
        self.axes.iter().try_fold(1_usize, |total, axis| {
            total
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
        if total != 0 {
            self.validate_axes()?;
        }
        Ok((0..total).map(move |ordinal| {
            let mut packet = self.base.clone();
            let mut stride = total;
            for axis in &self.axes {
                // An empty axis makes total zero, so no ordinal reaches here.
                stride /= axis.values.len();
                let value = &axis.values[(ordinal / stride) % axis.values.len()];
                let packet_len = packet.len();
                let layer = packet.layer_mut(axis.layer).ok_or(Error::LayerIndex {
                    index: axis.layer,
                    len: packet_len,
                })?;
                layer
                    .set_field(&axis.field, value.clone())
                    .map_err(|source| axis.error(source))?;
            }
            Ok(packet)
        }))
    }

    fn validate_axes(&self) -> Result<(), Error> {
        let mut fields = HashSet::new();
        for axis in &self.axes {
            let layer = self.base.layer(axis.layer).ok_or(Error::LayerIndex {
                index: axis.layer,
                len: self.base.len(),
            })?;
            let field = layer
                .schema()
                .fields
                .iter()
                .find(|field| {
                    field.name == axis.field || field.aliases.contains(&axis.field.as_str())
                })
                .ok_or_else(|| {
                    axis.error(FieldError::UnknownField {
                        protocol: *layer.protocol_id(),
                        field: axis.field.clone(),
                    })
                })?;
            if !fields.insert((axis.layer, field.name)) {
                return Err(Error::DuplicateAxis {
                    layer: axis.layer,
                    field: field.name.to_owned(),
                });
            }
            // Check each supplied value once before yielding any packets. Each
            // expanded packet still applies setters in declaration order.
            let mut editable = layer.clone_box();
            for value in &axis.values {
                editable
                    .set_field(&axis.field, value.clone())
                    .map_err(|source| axis.error(source))?;
            }
        }
        Ok(())
    }
}

impl TemplateAxis {
    fn error(&self, source: FieldError) -> Error {
        Error::Field {
            layer: self.layer,
            field: self.field.clone(),
            source,
        }
    }
}

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    #[error("template expansion count overflowed")]
    ExpansionOverflow,
    #[error("template expands to {requested} packets, exceeding limit {limit}")]
    ExpansionLimit { requested: usize, limit: usize },
    #[error("template repeats field {field} on layer {layer}")]
    DuplicateAxis { layer: usize, field: String },
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

impl Classified for Error {
    fn classification(&self) -> Classification {
        let code = match self {
            Self::ExpansionOverflow | Self::ExpansionLimit { .. } => "cli.template_limit",
            Self::DuplicateAxis { .. } => "cli.template_duplicate_axis",
            Self::LayerIndex { .. } | Self::Field { .. } => "cli.template_field",
        };
        Classification::new(
            code,
            Kind::Cli,
            Some(
                "use distinct writable fields and keep the Cartesian product within the packet limit",
            ),
        )
    }
}
