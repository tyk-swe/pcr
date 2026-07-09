// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use std::fmt;
use std::sync::Arc;

use thiserror::Error;

use super::{FieldError, FieldValue, Packet};

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
            } => end_inclusive
                .checked_sub(*start)
                .and_then(|span| span.checked_add(1))
                .and_then(|count| usize::try_from(count).ok()),
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
            next: 0,
            total,
        })
    }
}

pub struct PacketTemplateIter<'a> {
    template: &'a PacketTemplate,
    next: usize,
    total: usize,
}

impl Iterator for PacketTemplateIter<'_> {
    type Item = Result<Packet, TemplateError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.next >= self.total {
            return None;
        }
        let ordinal = self.next;
        self.next += 1;
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
        let remaining = self.total.saturating_sub(self.next);
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

pub trait PacketTransform {
    type Error;

    fn transform(&self, packet: Packet, maximum: usize) -> Result<Vec<Packet>, Self::Error>;
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;

    use super::*;
    use crate::core::Raw;

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
}
