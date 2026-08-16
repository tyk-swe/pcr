// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Packet layer models and reflection.

mod model;
mod reflection;

pub use model::{FieldError, FieldSchema};
pub use model::{
    Layer, LayerSchema as Schema, MalformedLayer as Malformed, Padding, ProtocolId as Id, Raw,
};
pub(crate) use model::{LayerSchema, MalformedLayer, ProtocolId};
#[doc(hidden)]
pub use model::{malformed_layout, padding_layout, raw_layout};
pub(crate) use reflection::reflective_layer;
#[doc(hidden)]
pub use reflection::{
    ReflectiveField, ReflectiveFieldError, reflect_get, reflect_set, reflect_set_bounded,
};
