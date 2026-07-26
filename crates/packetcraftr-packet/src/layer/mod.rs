// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Packet layer models and reflection.

pub(crate) mod model;
mod reflection;

#[doc(hidden)]
pub use model::{
    FieldError, FieldSchema, LayerSchema, MalformedLayer, ProtocolId, malformed_layout,
    padding_layout, raw_layout,
};
pub use model::{
    Layer, LayerSchema as Schema, MalformedLayer as Malformed, Padding, ProtocolId as Id, Raw,
};
#[doc(hidden)]
pub use reflection::{
    ReflectiveField, ReflectiveFieldError, reflect_get, reflect_set, reflective_layer,
};
