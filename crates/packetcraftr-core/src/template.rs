// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::HashSet;
use thiserror::Error;

use crate::error::{Classification, Classified, Kind};
use crate::field::{self, FieldValue, Path};
use crate::packet::Packet;

pub const DEFAULT_MAX_TEMPLATE_PACKETS: usize = 10_000;

/// An inclusive ascending unsigned range expanded by a template axis.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NumericRange {
    start: u64,
    end: u64,
    step: u64,
}

impl NumericRange {
    pub fn new(start: u64, end: u64, step: u64) -> Result<Self, Error> {
        if step == 0 {
            return Err(Error::InvalidRangeStep { step });
        }
        if start > end {
            return Err(Error::ReversedRange { start, end });
        }
        Ok(Self { start, end, step })
    }

    /// Number of values the range produces, in `u128` so a `0..=u64::MAX`
    /// span still reports its exact `u64::MAX + 1` length.
    pub fn len(&self) -> u128 {
        u128::from(self.end - self.start) / u128::from(self.step) + 1
    }

    pub fn is_empty(&self) -> bool {
        false
    }

    pub fn values(&self) -> impl Iterator<Item = FieldValue> + '_ {
        let (end, step) = (self.end, self.step);
        std::iter::successors(Some(self.start), move |value| {
            value.checked_add(step).filter(|next| *next <= end)
        })
        .map(FieldValue::Unsigned)
    }
}

#[derive(Clone, Debug)]
struct TemplateAxis {
    layer: usize,
    field: String,
    path: Option<Path>,
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
    /// stable, with the last axis varying fastest.
    #[must_use]
    pub fn axis(mut self, layer: usize, field: impl Into<String>, values: Vec<FieldValue>) -> Self {
        let field = field.into();
        self.axes.push(TemplateAxis {
            layer,
            path: field.parse().ok(),
            field,
            values,
        });
        self
    }

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

    /// Iterates the Cartesian product, refusing one larger than `maximum`.
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
                let path = axis.path.as_ref().ok_or_else(|| {
                    axis.error(field::Error::UnknownField {
                        protocol: *layer.protocol_id(),
                        field: axis.field.clone(),
                    })
                })?;
                layer
                    .set_field_path(path, value.clone())
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
            let unknown = || {
                axis.error(field::Error::UnknownField {
                    protocol: *layer.protocol_id(),
                    field: axis.field.clone(),
                })
            };
            let path = axis.path.as_ref().ok_or_else(unknown)?;
            path.schema(layer.schema()).ok_or_else(unknown)?;
            let root = layer
                .schema()
                .fields
                .iter()
                .find(|field| field.name == path.root() || field.aliases.contains(&path.root()))
                .ok_or_else(unknown)?;
            let canonical = path.canonical(root.name);
            if !fields.insert((axis.layer, canonical.clone())) {
                return Err(Error::DuplicateAxis {
                    layer: axis.layer,
                    field: canonical,
                });
            }
            let mut editable = layer.clone_box();
            for value in &axis.values {
                editable
                    .set_field_path(path, value.clone())
                    .map_err(|source| axis.error(source))?;
            }
        }
        Ok(())
    }
}

impl TemplateAxis {
    fn error(&self, source: field::Error) -> Error {
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
    #[error("template range step {step} is not a positive integer")]
    InvalidRangeStep { step: u64 },
    #[error("template range {start}..{end} is reversed; ranges ascend to an inclusive end")]
    ReversedRange { start: u64, end: u64 },
    #[error("template layer index {index} is outside packet length {len}")]
    LayerIndex { index: usize, len: usize },
    #[error("could not set template field {field} on layer {layer}")]
    Field {
        layer: usize,
        field: String,
        #[source]
        source: field::Error,
    },
}

impl Classified for Error {
    fn classification(&self) -> Classification {
        let code = match self {
            Self::ExpansionOverflow | Self::ExpansionLimit { .. } => "cli.template_limit",
            Self::DuplicateAxis { .. } => "cli.template_duplicate_axis",
            Self::InvalidRangeStep { .. } | Self::ReversedRange { .. } => "cli.template_range",
            Self::LayerIndex { .. } | Self::Field { .. } => "cli.template_field",
        };
        let hint = match self {
            Self::InvalidRangeStep { .. } | Self::ReversedRange { .. } => {
                "write ascending unsigned ranges like 1..64 or 1..64:8 with a positive step"
            }
            _ => {
                "use distinct writable fields and keep the Cartesian product within the packet limit"
            }
        };
        Classification::new(code, Kind::Usage, Some(hint))
    }
}
