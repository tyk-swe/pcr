// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Packet layer models and reflection, including the opaque `Raw`, `Padding`,
//! and `Malformed` layers every protocol can fall back to.
//!
//! A protocol outside this crate declares its layer with
//! [`reflective_layer!`](crate::reflective_layer). Fields reflect through
//! [`ReflectiveField`]; handwritten accessors use [`reflect_get`],
//! [`reflect_set`], and [`reflect_set_bounded`] so their errors name the field
//! the same way the declared ones do.

mod model;
mod opaque;
mod reflection;

pub use model::{FieldSchema, Id, Layer, Schema};
pub use opaque::{Malformed, Padding, Raw, parse_hex};
pub(crate) use opaque::{MalformedCodec, PaddingCodec, RawCodec};
pub(crate) use reflection::reflective_layer;
pub use reflection::{ReflectiveField, Refusal, reflect_get, reflect_set, reflect_set_bounded};
