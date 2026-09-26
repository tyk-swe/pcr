// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Packet layer models and reflection.

mod model;
mod reflection;

pub use model::{FieldError, FieldSchema};
pub use model::{Id, Layer, Malformed, Padding, Raw, Schema};
// Codecs outside core call `raw_layout` to describe an opaque `Raw` layer; it
// stays out of the documented API.
#[doc(hidden)]
pub use model::raw_layout;
pub(crate) use model::{
    malformed_layout, malformed_schema, padding_layout, padding_schema, raw_schema,
};
pub(crate) use reflection::reflective_layer;
#[doc(hidden)]
pub use reflection::{
    ReflectiveField, ReflectiveFieldError, reflect_get, reflect_set, reflect_set_bounded,
};
