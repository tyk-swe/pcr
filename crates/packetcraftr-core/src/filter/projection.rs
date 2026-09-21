// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Field-only queries sharing filter path resolution and evaluation.

use super::{
    Context, Requirements,
    ast::{Op, Predicate},
    eval, parser,
    path::{FieldRef, FieldSource},
};
use crate::{
    error::{Classification, Classified, Kind},
    field::FieldValue,
    registry::Registry,
};

#[derive(Clone, Debug)]
pub struct Projection {
    columns: Vec<String>,
    fields: Vec<FieldRef>,
    requirements: Requirements,
}
#[derive(Clone, Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ProjectionError {
    #[error("invalid projection field: {0}")]
    Field(#[from] super::Error),
    #[error("projection exceeds {field}={limit}")]
    Limit { field: &'static str, limit: usize },
}
impl Classified for ProjectionError {
    fn classification(&self) -> Classification {
        match self {
            Self::Field(_) => Classification::new(
                "cli.projection_field",
                Kind::Cli,
                Some("select registered field paths"),
            ),
            Self::Limit { .. } => Classification::new(
                "policy.projection_limit",
                Kind::Policy,
                Some("select fewer or smaller fields within the finite projection budget"),
            ),
        }
    }
}

impl Projection {
    /// Compiles 1..=256 ordered columns under the shared 64 KiB path budget.
    pub fn compile<'a>(
        columns: impl IntoIterator<Item = &'a str>,
        registry: &Registry,
    ) -> Result<Self, ProjectionError> {
        let mut projection = Self {
            columns: Vec::new(),
            fields: Vec::new(),
            requirements: Requirements::default(),
        };
        let mut bytes = 0usize;
        for column in columns {
            if projection.fields.len() >= 256 {
                return Err(ProjectionError::Limit {
                    field: "columns",
                    limit: 256,
                });
            }
            bytes = bytes
                .checked_add(column.len())
                .filter(|bytes| *bytes <= parser::DEFAULT_MAX_FILTER_BYTES)
                .ok_or(ProjectionError::Limit {
                    field: "field_path_bytes",
                    limit: parser::DEFAULT_MAX_FILTER_BYTES,
                })?;
            let compiled = parser::compile(
                column,
                registry,
                &parser::Options {
                    max_terms: 1,
                    ..Default::default()
                },
            )?;
            let [Op::Leaf(Predicate::Bare { field, .. })] = compiled.program.as_slice() else {
                return Err(super::Error::Syntax {
                    offset: 0,
                    message: "projection requires one field path per column".to_owned(),
                }
                .into());
            };
            projection.columns.push(field.path.clone());
            projection.fields.push(field.clone());
            projection.requirements.stream_index |= compiled.requirements.stream_index;
            projection.requirements.tcp_stream |= compiled.requirements.tcp_stream;
            projection.requirements.udp_stream |= compiled.requirements.udp_stream;
            projection.requirements.timestamp |= compiled.requirements.timestamp;
        }
        if projection.fields.is_empty() {
            return Err(super::Error::Empty.into());
        }
        Ok(projection)
    }
    pub fn columns(&self) -> &[String] {
        &self.columns
    }
    pub fn requirements(&self) -> Requirements {
        self.requirements
    }

    /// Whether each column selects one value independently of later layer
    /// occurrences. A scalar result alone does not establish this: an
    /// unqualified layer path can have additional, undecoded occurrences.
    pub(crate) fn selects_single_values(&self) -> impl Iterator<Item = bool> + '_ {
        self.fields.iter().map(|field| match &field.source {
            FieldSource::Frame(_) | FieldSource::Stream(_) => true,
            FieldSource::NestedLayer { occurrence, .. } => occurrence.is_some(),
            FieldSource::Layer {
                binding,
                occurrence,
            } => occurrence.is_some() && binding.fields().len() == 1,
        })
    }

    /// Independent columns for consumers that must retain earlier successful
    /// evidence when a later column exhausts a shared projection budget.
    pub(crate) fn single_columns(&self) -> Vec<Self> {
        self.columns
            .iter()
            .zip(&self.fields)
            .map(|(column, field)| Self {
                columns: vec![column.clone()],
                fields: vec![field.clone()],
                // A conservative superset; never hide a required context.
                requirements: self.requirements,
            })
            .collect()
    }

    /// Missing fields are `None`; repeated occurrences become ordered lists.
    /// The ceiling counts compact JSON cell bytes (byte values encoded as hex),
    /// before cloning values into the result. Container nesting is capped at 64.
    pub fn values(
        &self,
        context: &Context<'_>,
        max_bytes: usize,
    ) -> Result<Vec<Option<FieldValue>>, ProjectionError> {
        let mut remaining = max_bytes;
        self.values_with_budget(context, &mut remaining)
    }

    /// Projects cells while charging a budget shared with other projections.
    pub(crate) fn values_with_budget(
        &self,
        context: &Context<'_>,
        remaining: &mut usize,
    ) -> Result<Vec<Option<FieldValue>>, ProjectionError> {
        let max_bytes = *remaining;
        let limit = || ProjectionError::Limit {
            field: "cell_bytes",
            limit: max_bytes,
        };
        let mut row = Vec::new();
        for field in &self.fields {
            let mut values = Vec::new();
            let mut exceeded = false;
            eval::each_value(context, field, |value| {
                let Some(bytes) = measure(&value, *remaining, 0) else {
                    exceeded = true;
                    return true;
                };
                *remaining -= bytes;
                let mut value = value.into_owned();
                detach_bytes(&mut value);
                values.push(value);
                false
            });
            if exceeded {
                return Err(limit());
            }
            row.push(match values.len() {
                0 => {
                    *remaining = remaining.checked_sub(4).ok_or_else(limit)?;
                    None
                }
                1 => values.pop(),
                _ => {
                    *remaining = remaining.checked_sub(values.len() + 1).ok_or_else(limit)?;
                    Some(FieldValue::List(values))
                }
            });
        }
        Ok(row)
    }
}

// Retained cells are charged by their visible bytes. A small decoded slice
// must not keep an entire source frame alive behind that charge.
fn detach_bytes(value: &mut FieldValue) {
    match value {
        FieldValue::Bytes(bytes) => *bytes = bytes::Bytes::copy_from_slice(bytes),
        FieldValue::List(values) => values.iter_mut().for_each(detach_bytes),
        FieldValue::Object(values) => values.values_mut().for_each(detach_bytes),
        _ => {}
    }
}

fn string_size(value: &str) -> Option<usize> {
    value.bytes().try_fold(2usize, |total, byte| {
        total.checked_add(match byte {
            b'"' | b'\\' | 8 | 9 | 10 | 12 | 13 => 2,
            0..=31 => 6,
            _ => 1,
        })
    })
}

/// Decimal digit count of an unsigned value, counted rather than rendered.
fn unsigned_len(value: u64) -> usize {
    value
        .checked_ilog10()
        .map_or(1, |digits| digits as usize + 1)
}

/// The exact length of a `Display` rendering, counted without allocating.
///
/// The cell budget needs the encoded size, not the string, so address-like
/// values — IPv6's `::` elision above all — are measured by writing them into
/// a sink that keeps only the byte count.
fn display_len(value: impl std::fmt::Display) -> usize {
    use std::fmt::Write;

    struct Counter(usize);
    impl std::fmt::Write for Counter {
        fn write_str(&mut self, text: &str) -> std::fmt::Result {
            self.0 += text.len();
            Ok(())
        }
    }
    let mut counter = Counter(0);
    // A byte-counting sink cannot fail.
    let _ = write!(counter, "{value}");
    counter.0
}

fn measure(value: &FieldValue, maximum: usize, depth: usize) -> Option<usize> {
    if depth > 64 {
        return None;
    }
    let bytes = match value {
        FieldValue::Bool(value) => {
            if *value {
                4
            } else {
                5
            }
        }
        FieldValue::Unsigned(value) => unsigned_len(*value),
        FieldValue::Signed(value) => {
            unsigned_len(value.unsigned_abs()) + usize::from(value.is_negative())
        }
        FieldValue::Ipv4(_) | FieldValue::Ipv6(_) | FieldValue::Mac(_) => display_len(value) + 2,
        FieldValue::Text(value) => string_size(value)?,
        FieldValue::Bytes(value) => value.len().checked_mul(2)?.checked_add(2)?,
        FieldValue::List(values) => {
            let mut size = 2usize.checked_add(values.len().saturating_sub(1))?;
            for value in values {
                size = size.checked_add(measure(value, maximum.checked_sub(size)?, depth + 1)?)?;
            }
            size
        }
        FieldValue::Object(values) => {
            let mut size = 2usize.checked_add(values.len().saturating_sub(1))?;
            for (key, value) in values {
                size = size.checked_add(string_size(key)?)?.checked_add(1)?;
                size = size.checked_add(measure(value, maximum.checked_sub(size)?, depth + 1)?)?;
            }
            size
        }
    };
    (bytes <= maximum).then_some(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    /// The cell encoding the budget accounts for: bare scalars, hex bytes and
    /// `Display` addresses as quoted strings, and serde's escaping for text.
    fn cell_len(value: &FieldValue) -> usize {
        match value {
            FieldValue::Bool(value) => {
                if *value {
                    4
                } else {
                    5
                }
            }
            FieldValue::Unsigned(value) => value.to_string().len(),
            FieldValue::Signed(value) => value.to_string().len(),
            FieldValue::Text(value) => serde_json::to_string(value).expect("text encodes").len(),
            FieldValue::Bytes(value) => value.len() * 2 + 2,
            FieldValue::Ipv4(_) | FieldValue::Ipv6(_) | FieldValue::Mac(_) => {
                value.to_string().len() + 2
            }
            FieldValue::List(values) => {
                2 + values.len().saturating_sub(1) + values.iter().map(cell_len).sum::<usize>()
            }
            FieldValue::Object(values) => {
                2 + values.len().saturating_sub(1)
                    + values
                        .iter()
                        .map(|(key, value)| {
                            serde_json::to_string(key).expect("key encodes").len()
                                + 1
                                + cell_len(value)
                        })
                        .sum::<usize>()
            }
        }
    }

    /// The budget's cell accounting must match the encoded rendering exactly,
    /// at every edge the counted helpers replace a formatted string for.
    #[test]
    fn measured_sizes_equal_the_rendered_encoding() {
        let cases = [
            FieldValue::Bool(true),
            FieldValue::Bool(false),
            FieldValue::Unsigned(0),
            FieldValue::Unsigned(9),
            FieldValue::Unsigned(u64::MAX),
            FieldValue::Signed(0),
            FieldValue::Signed(-1),
            FieldValue::Signed(i64::MIN),
            FieldValue::Signed(i64::MAX),
            FieldValue::Ipv4(Ipv4Addr::new(0, 0, 0, 0)),
            FieldValue::Ipv4(Ipv4Addr::new(255, 255, 255, 255)),
            FieldValue::Ipv6(Ipv6Addr::UNSPECIFIED),
            FieldValue::Ipv6(Ipv6Addr::LOCALHOST),
            FieldValue::Ipv6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x1234)),
            // Equal-length zero runs elide the first; a single zero segment
            // never elides.
            FieldValue::Ipv6(Ipv6Addr::new(1, 0, 0, 2, 0, 0, 3, 4)),
            FieldValue::Ipv6(Ipv6Addr::new(1, 2, 3, 4, 5, 0, 7, 8)),
            FieldValue::Ipv6(Ipv6Addr::new(
                0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff,
            )),
            FieldValue::Mac([0, 0, 0, 0, 0, 0]),
            FieldValue::Mac([0xff; 6]),
            FieldValue::Text("plain".to_owned()),
            FieldValue::Text("esc\"aped\\\n\t\u{7}text".to_owned()),
            FieldValue::Text("ünïcödé — 日本語".to_owned()),
            FieldValue::Bytes(bytes::Bytes::from_static(&[0, 0xab, 0xff])),
            FieldValue::Bytes(bytes::Bytes::new()),
            FieldValue::List(vec![
                FieldValue::Unsigned(1),
                FieldValue::Text("two".to_owned()),
            ]),
            FieldValue::List(Vec::new()),
            FieldValue::Object(
                [("key".to_owned(), FieldValue::Signed(-7))]
                    .into_iter()
                    .collect(),
            ),
        ];
        for value in &cases {
            assert_eq!(
                measure(value, usize::MAX, 0),
                Some(cell_len(value)),
                "{value:?} measured differently than its encoding"
            );
        }
    }
}
