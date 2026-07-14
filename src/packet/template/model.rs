// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::fmt;
use std::sync::Arc;

use thiserror::Error;

use super::super::Packet;
use super::super::field::FieldValue;
use super::super::layer::FieldError;

pub const DEFAULT_MAX_TEMPLATE_PACKETS: usize = 10_000;

#[derive(Clone)]
pub enum TemplateValues {
    Values(Vec<FieldValue>),
    UnsignedRange {
        start: u64,
        end_inclusive: u64,
    },
    Generated {
        count: usize,
        generator: Arc<dyn Fn(usize) -> FieldValue + Send + Sync>,
    },
}

impl fmt::Debug for TemplateValues {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Values(values) => formatter.debug_tuple("Values").field(values).finish(),
            Self::UnsignedRange {
                start,
                end_inclusive,
            } => formatter
                .debug_struct("UnsignedRange")
                .field("start", start)
                .field("end_inclusive", end_inclusive)
                .finish(),
            Self::Generated { count, .. } => formatter
                .debug_struct("Generated")
                .field("count", count)
                .finish_non_exhaustive(),
        }
    }
}

impl TemplateValues {
    fn len(&self) -> Option<usize> {
        match self {
            Self::Values(values) => Some(values.len()),
            Self::UnsignedRange {
                start,
                end_inclusive,
            } => {
                if start > end_inclusive {
                    Some(0)
                } else {
                    end_inclusive
                        .checked_sub(*start)
                        .and_then(|span| span.checked_add(1))
                        .and_then(|count| usize::try_from(count).ok())
                }
            }
            Self::Generated { count, .. } => Some(*count),
        }
    }

    fn value(&self, index: usize) -> Option<FieldValue> {
        match self {
            Self::Values(values) => values.get(index).cloned(),
            Self::UnsignedRange {
                start,
                end_inclusive,
            } => {
                let value = start.checked_add(index as u64)?;
                (value <= *end_inclusive).then_some(FieldValue::Unsigned(value))
            }
            Self::Generated { count, generator } => (index < *count).then(|| generator(index)),
        }
    }
}

#[derive(Clone, Debug)]
struct TemplateAxis {
    layer: usize,
    field: String,
    values: TemplateValues,
}

#[derive(Clone, Debug)]
pub struct PacketTemplate {
    base: Packet,
    axes: Vec<TemplateAxis>,
}

impl PacketTemplate {
    pub fn new(base: Packet) -> Self {
        Self {
            base,
            axes: Vec::new(),
        }
    }

    pub fn base(&self) -> &Packet {
        &self.base
    }

    #[must_use]
    pub fn axis(mut self, layer: usize, field: impl Into<String>, values: TemplateValues) -> Self {
        self.axes.push(TemplateAxis {
            layer,
            field: field.into(),
            values,
        });
        self
    }

    pub fn expansion_len(&self) -> Result<usize, TemplateError> {
        if self.axes.is_empty() {
            return Ok(1);
        }
        self.axes.iter().try_fold(1usize, |product, axis| {
            let length = axis.values.len().ok_or(TemplateError::ExpansionOverflow)?;
            product
                .checked_mul(length)
                .ok_or(TemplateError::ExpansionOverflow)
        })
    }

    pub fn expand(&self, maximum: usize) -> Result<PacketTemplateIter<'_>, TemplateError> {
        let total = self.expansion_len()?;
        if total > maximum {
            return Err(TemplateError::ExpansionLimit {
                requested: total,
                limit: maximum,
            });
        }
        Ok(PacketTemplateIter {
            template: self,
            next_ordinal: 0,
            total,
        })
    }
}

pub struct PacketTemplateIter<'a> {
    template: &'a PacketTemplate,
    next_ordinal: usize,
    total: usize,
}

impl Iterator for PacketTemplateIter<'_> {
    type Item = Result<Packet, TemplateError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.next_ordinal >= self.total {
            return None;
        }
        let ordinal = self.next_ordinal;
        self.next_ordinal += 1;
        let mut packet = self.template.base.clone();
        let mut divisor = self.total;
        for axis in &self.template.axes {
            let Some(length) = axis.values.len() else {
                return Some(Err(TemplateError::ExpansionOverflow));
            };
            if length == 0 {
                return None;
            }
            divisor /= length;
            let index = (ordinal / divisor) % length;
            let Some(value) = axis.values.value(index) else {
                return Some(Err(TemplateError::ExpansionOverflow));
            };
            let Some(layer) = packet.layer_mut(axis.layer) else {
                return Some(Err(TemplateError::LayerIndex {
                    index: axis.layer,
                    len: packet.len(),
                }));
            };
            if let Err(source) = layer.set_field(&axis.field, value) {
                return Some(Err(TemplateError::Field {
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

impl ExactSizeIterator for PacketTemplateIter<'_> {}

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum TemplateError {
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

#[cfg(test)]
mod tests {
    use bytes::Bytes;

    use super::*;
    use crate::packet::layer::Raw;

    #[test]
    fn expansion_is_lazy_bounded_and_deterministic() {
        let mut packet = Packet::new();
        packet.push(Raw::new(Bytes::new()));
        let template = PacketTemplate::new(packet).axis(
            0,
            "bytes",
            TemplateValues::Values(vec![
                FieldValue::Bytes(Bytes::from_static(b"a")),
                FieldValue::Bytes(Bytes::from_static(b"b")),
            ]),
        );
        assert!(matches!(
            template.expand(1),
            Err(TemplateError::ExpansionLimit {
                requested: 2,
                limit: 1
            })
        ));
        let values = template
            .expand(2)
            .unwrap()
            .map(|packet| packet.unwrap().get::<Raw>().unwrap().bytes.clone())
            .collect::<Vec<_>>();
        assert_eq!(values, [Bytes::from_static(b"a"), Bytes::from_static(b"b")]);
    }

    #[test]
    fn reversed_unsigned_range_is_empty_instead_of_overflowing() {
        let template = PacketTemplate::new(Packet::new()).axis(
            0,
            "unused",
            TemplateValues::UnsignedRange {
                start: 2,
                end_inclusive: 1,
            },
        );

        assert_eq!(template.expansion_len().unwrap(), 0);
        assert_eq!(template.expand(0).unwrap().count(), 0);
    }
}
