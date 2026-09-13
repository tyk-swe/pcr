// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::{frame::SourceFrame, stream::StreamRecord};
use packetcraftr_core::field::FieldValue;
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
#[derive(Serialize)]
pub struct RowEvent<'a> {
    pub columns: &'a [String],
    #[serde(flatten)]
    pub row: &'a Row,
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
#[derive(Serialize)]
pub struct Report {
    #[serde(flatten)]
    pub summary: Complete,
    pub rows: Vec<Row>,
}
