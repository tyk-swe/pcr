// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::field::FieldValue;

pub const PACKET_DOCUMENT_SCHEMA_V1: &str = "packetcraftr.packet/v1";
pub const DEFAULT_MAX_DOCUMENT_BYTES: usize = 16 * 1024 * 1024;
/// Absolute recursive `FieldValue::List` nesting accepted by the stable
/// packet-document parser.
pub const MAX_DOCUMENT_NESTING: usize = 64;
pub const DEFAULT_MAX_DOCUMENT_NESTING: usize = MAX_DOCUMENT_NESTING;

pub(super) const DOCUMENT_BASE_CONTAINER_DEPTH: usize = 6;
pub(super) const LAYER_LIMIT_SENTINEL: &str = "$__packetcraftr_document_layer_limit";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Format {
    Json,
    Yaml,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Packet {
    pub schema: String,
    pub layers: Vec<Layer>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Layer {
    pub protocol: String,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub fields: BTreeMap<String, FieldValue>,
}
