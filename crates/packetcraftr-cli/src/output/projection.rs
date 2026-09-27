// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::{contract::Error, frame::SourceFrame, stream::StreamRecord};
use packetcraftr_core::field::FieldValue;
use packetcraftr_core::filter::Projection;
use serde::{
    Serialize, Serializer,
    ser::{Error as _, SerializeMap, SerializeSeq},
};

/// Compact cell serialization: addresses/MACs are text, bytes are lowercase hex.
pub struct Cell<'a>(pub &'a FieldValue);
impl Serialize for Cell<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self.0 {
            FieldValue::Bool(v) => serializer.serialize_bool(*v),
            FieldValue::Unsigned(v) => serializer.serialize_u64(*v),
            FieldValue::Signed(v) => serializer.serialize_i64(*v),
            FieldValue::Text(v) => serializer.serialize_str(v),
            FieldValue::Bytes(v) => serializer.collect_str(&super::hex::CompactHex(v)),
            FieldValue::Ipv4(_) | FieldValue::Ipv6(_) | FieldValue::Mac(_) => {
                serializer.collect_str(self.0)
            }
            FieldValue::List(values) => {
                let mut seq = serializer.serialize_seq(Some(values.len()))?;
                for value in values {
                    seq.serialize_element(&Cell(value))?;
                }
                seq.end()
            }
            FieldValue::Object(values) => {
                let mut map = serializer.serialize_map(Some(values.len()))?;
                for (key, value) in values {
                    map.serialize_entry(key, &Cell(value))?;
                }
                map.end()
            }
            _ => Err(S::Error::custom("unsupported projected value type")),
        }
    }
}
fn values<S: Serializer>(values: &[Option<FieldValue>], serializer: S) -> Result<S::Ok, S::Error> {
    let mut seq = serializer.serialize_seq(Some(values.len()))?;
    for value in values {
        seq.serialize_element(&value.as_ref().map(Cell))?;
    }
    seq.end()
}
#[derive(Clone, Debug, Serialize)]
pub struct Row {
    pub source_frame: SourceFrame,
    #[serde(serialize_with = "values")]
    pub values: Vec<Option<FieldValue>>,
}
/// A frame's projected cells, at its one-based source position.
impl TryFrom<(u64, Vec<Option<FieldValue>>)> for Row {
    type Error = Error;

    fn try_from((source_frame, values): (u64, Vec<Option<FieldValue>>)) -> Result<Self, Error> {
        Ok(Self {
            source_frame: source_frame.try_into()?,
            values,
        })
    }
}
#[derive(Serialize)]
pub struct RowEvent<'a> {
    pub columns: &'a [String],
    #[serde(flatten)]
    pub row: &'a Row,
}
/// One row under the projection's column names.
impl<'a> From<(&'a Projection, &'a Row)> for RowEvent<'a> {
    fn from((projection, row): (&'a Projection, &'a Row)) -> Self {
        Self {
            columns: projection.columns(),
            row,
        }
    }
}
impl StreamRecord for RowEvent<'_> {
    fn event_name(&self) -> &'static str {
        "fields"
    }
}
#[derive(Debug, Serialize)]
pub struct Complete {
    pub columns: Vec<String>,
    pub rows_written: u64,
    pub frames_read: u64,
    pub captured_bytes_read: u64,
}
/// The projection's columns, the rows written, and the frames and captured
/// bytes read.
impl From<(&Projection, u64, u64, u64)> for Complete {
    fn from(
        (projection, rows_written, frames_read, captured_bytes_read): (&Projection, u64, u64, u64),
    ) -> Self {
        Self {
            columns: projection.columns().to_vec(),
            rows_written,
            frames_read,
            captured_bytes_read,
        }
    }
}
#[derive(Serialize)]
pub struct Report {
    #[serde(flatten)]
    pub summary: Complete,
    pub rows: Vec<Row>,
}
/// The terminal counters and every retained row.
impl From<(Complete, Vec<Row>)> for Report {
    fn from((summary, rows): (Complete, Vec<Row>)) -> Self {
        Self { summary, rows }
    }
}
