// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::BTreeMap;
use std::fmt;

use serde::Serialize;

use super::error::Error;
use crate::field::FieldValue;

pub const PACKET_DOCUMENT_SCHEMA_V1: &str = "packetcraftr.packet/v1";
pub const DEFAULT_MAX_DOCUMENT_BYTES: usize = 16 * 1024 * 1024;
/// Absolute recursive `FieldValue::List` nesting accepted by the stable
/// packet-document parser.
pub const MAX_DOCUMENT_NESTING: usize = 64;
pub const DEFAULT_MAX_DOCUMENT_NESTING: usize = MAX_DOCUMENT_NESTING;

pub(super) const DOCUMENT_BASE_CONTAINER_DEPTH: usize = 6;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Format {
    Json,
    Yaml,
}

/// Resource envelope one packet document may occupy while it is parsed.
///
/// Every limit is enforced inside the JSON and YAML deserializers, before the
/// bounded item is allocated or inserted, so the two formats accept exactly
/// the same documents. [`DocumentLimits::default`] is conservative for the
/// documents the registry can describe and is far below the raw byte ceiling;
/// widen individual fields with struct update syntax.
///
/// Payload bytes count the retained value width: text and byte values their
/// length, and fixed-width scalars their wire width (booleans one byte,
/// integers eight, IPv4 four, IPv6 sixteen, MAC six).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DocumentLimits {
    /// Maximum UTF-8 input bytes, checked before any parsing.
    pub max_input_bytes: usize,
    /// Maximum layers in the document.
    pub max_layers: usize,
    /// Maximum recursive `FieldValue::List` nesting; at most
    /// [`MAX_DOCUMENT_NESTING`].
    pub max_nesting: usize,
    /// Maximum reflective fields in one layer.
    pub max_fields_per_layer: usize,
    /// Maximum field-value nodes (scalars and lists) across the document.
    pub max_total_nodes: usize,
    /// Maximum items in one list value.
    pub max_list_items: usize,
    /// Maximum list items summed across every list in the document.
    pub max_total_list_items: usize,
    /// Maximum bytes in one protocol name.
    pub max_protocol_name_bytes: usize,
    /// Maximum bytes in one field name.
    pub max_field_name_bytes: usize,
    /// Maximum bytes in one text value (or the schema string).
    pub max_text_bytes: usize,
    /// Maximum bytes in one byte value.
    pub max_byte_value_bytes: usize,
    /// Maximum retained payload bytes summed across every value.
    pub max_total_payload_bytes: usize,
}

impl DocumentLimits {
    /// The stable defaults every simple parse entry point uses.
    pub const DEFAULT: Self = Self {
        max_input_bytes: DEFAULT_MAX_DOCUMENT_BYTES,
        max_layers: crate::layout::DEFAULT_MAX_LAYERS,
        max_nesting: DEFAULT_MAX_DOCUMENT_NESTING,
        max_fields_per_layer: 256,
        max_total_nodes: 65_536,
        max_list_items: 4_096,
        max_total_list_items: 32_768,
        max_protocol_name_bytes: 64,
        max_field_name_bytes: 128,
        max_text_bytes: 64 * 1024,
        max_byte_value_bytes: 1024 * 1024,
        max_total_payload_bytes: 4 * 1024 * 1024,
    };

    /// Rejects limits the stable parser cannot honor.
    pub fn validate(&self) -> Result<(), Error> {
        if self.max_nesting > MAX_DOCUMENT_NESTING {
            return Err(Error::InvalidLimit {
                field: "max_nesting",
                value: self.max_nesting,
                maximum: MAX_DOCUMENT_NESTING,
            });
        }
        Ok(())
    }

    /// The configured maximum for `limit`.
    #[must_use]
    pub const fn maximum(&self, limit: Limit) -> usize {
        match limit {
            Limit::InputBytes => self.max_input_bytes,
            Limit::Layers => self.max_layers,
            Limit::Nesting => self.max_nesting,
            Limit::FieldsPerLayer => self.max_fields_per_layer,
            Limit::TotalNodes => self.max_total_nodes,
            Limit::ListItems => self.max_list_items,
            Limit::TotalListItems => self.max_total_list_items,
            Limit::ProtocolNameBytes => self.max_protocol_name_bytes,
            Limit::FieldNameBytes => self.max_field_name_bytes,
            Limit::TextBytes => self.max_text_bytes,
            Limit::ByteValueBytes => self.max_byte_value_bytes,
            Limit::TotalPayloadBytes => self.max_total_payload_bytes,
        }
    }
}

impl Default for DocumentLimits {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// Which [`DocumentLimits`] field a rejected document exceeded.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Limit {
    InputBytes,
    Layers,
    Nesting,
    FieldsPerLayer,
    TotalNodes,
    ListItems,
    TotalListItems,
    ProtocolNameBytes,
    FieldNameBytes,
    TextBytes,
    ByteValueBytes,
    TotalPayloadBytes,
}

impl Limit {
    /// Every limit, in [`DocumentLimits`] field order.
    pub const ALL: [Self; 12] = [
        Self::InputBytes,
        Self::Layers,
        Self::Nesting,
        Self::FieldsPerLayer,
        Self::TotalNodes,
        Self::ListItems,
        Self::TotalListItems,
        Self::ProtocolNameBytes,
        Self::FieldNameBytes,
        Self::TextBytes,
        Self::ByteValueBytes,
        Self::TotalPayloadBytes,
    ];

    /// The stable `DocumentLimits` field name for this limit.
    #[must_use]
    pub const fn field(self) -> &'static str {
        match self {
            Self::InputBytes => "max_input_bytes",
            Self::Layers => "max_layers",
            Self::Nesting => "max_nesting",
            Self::FieldsPerLayer => "max_fields_per_layer",
            Self::TotalNodes => "max_total_nodes",
            Self::ListItems => "max_list_items",
            Self::TotalListItems => "max_total_list_items",
            Self::ProtocolNameBytes => "max_protocol_name_bytes",
            Self::FieldNameBytes => "max_field_name_bytes",
            Self::TextBytes => "max_text_bytes",
            Self::ByteValueBytes => "max_byte_value_bytes",
            Self::TotalPayloadBytes => "max_total_payload_bytes",
        }
    }
}

impl fmt::Display for Limit {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.field())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Packet {
    pub schema: String,
    pub layers: Vec<Layer>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Layer {
    pub protocol: String,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub fields: BTreeMap<String, FieldValue>,
}

impl Packet {
    pub fn validate_schema(&self) -> Result<(), Error> {
        if self.schema != PACKET_DOCUMENT_SCHEMA_V1 {
            return Err(Error::Schema {
                actual: self.schema.clone(),
                expected: PACKET_DOCUMENT_SCHEMA_V1,
            });
        }
        Ok(())
    }
}
