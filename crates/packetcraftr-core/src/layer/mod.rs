// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Packet layer models and reflection.

mod model;
mod reflection;

pub use model::{FieldError, FieldSchema};
pub use model::{Id, Layer, Malformed, Padding, Raw, Schema};
#[doc(hidden)]
pub use model::{malformed_layout, padding_layout, raw_layout};
pub(crate) use reflection::reflective_layer;
#[doc(hidden)]
pub use reflection::{
    ReflectiveField, ReflectiveFieldError, reflect_get, reflect_set, reflect_set_bounded,
};
