// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Packet layer models and reflection.

mod dynamic;
mod model;
mod reflection;
mod schema;

pub use packetcraftr_model::ProtocolId as Id;
pub use packetcraftr_model::{FieldId, ProtocolId};

pub use dynamic::DynamicLayer;
pub use model::{FieldError, Layer, MalformedLayer};
pub use model::{MalformedLayer as Malformed, Padding, Raw};
pub use model::{malformed_layout, padding_layout, raw_layout};
pub use reflection::{reflect_get, reflect_set, reflective_layer};
pub use schema::{
    FieldConstraints, FieldSchema, FieldSetError, LayerSchema, LengthRange,
    MAX_CONSTRAINED_LIST_ITEMS, MAX_CONSTRAINED_VALUE_BYTES, MAX_FIELD_DESCRIPTION_BYTES,
    MAX_SCHEMA_ALIASES, MAX_SCHEMA_DISPLAY_NAME_BYTES, MAX_SCHEMA_FIELDS, SchemaError, SignedRange,
    UnsignedRange, ValidatedFieldSet,
};
pub use schema::{FieldSchema as Field, LayerSchema as Schema};
