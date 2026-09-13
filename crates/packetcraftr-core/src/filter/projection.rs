// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Field-only queries sharing filter path resolution and evaluation.

use super::{
    Context, Requirements,
    ast::{Op, Predicate},
    eval, parser,
    path::FieldRef,
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

    /// Missing fields are `None`; repeated occurrences become ordered lists.
    /// The ceiling counts compact JSON cell bytes (byte values encoded as hex),
    /// before cloning values into the result. Container nesting is capped at 64.
    pub fn values(
        &self,
        context: &Context<'_>,
        max_bytes: usize,
    ) -> Result<Vec<Option<FieldValue>>, ProjectionError> {
        let limit = || ProjectionError::Limit {
            field: "cell_bytes",
            limit: max_bytes,
        };
        let mut remaining = max_bytes;
        let mut row = Vec::new();
        for field in &self.fields {
            let mut values = Vec::new();
            let mut exceeded = false;
            eval::any_value(context, field, |value| {
                let Some(bytes) = measure(value, remaining, 0) else {
                    exceeded = true;
                    return true;
                };
                remaining -= bytes;
                values.push(value.clone());
                false
            });
            if exceeded {
                return Err(limit());
            }
            row.push(match values.len() {
                0 => {
                    remaining = remaining.checked_sub(4).ok_or_else(limit)?;
                    None
                }
                1 => values.pop(),
                _ => {
                    remaining = remaining.checked_sub(values.len() + 1).ok_or_else(limit)?;
                    Some(FieldValue::List(values))
                }
            });
        }
        Ok(row)
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
        FieldValue::Unsigned(value) => value.to_string().len(),
        FieldValue::Signed(value) => value.to_string().len(),
        FieldValue::Ipv4(_) | FieldValue::Ipv6(_) | FieldValue::Mac(_) => {
            value.to_string().len() + 2
        }
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
