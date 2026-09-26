// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Packet layer models and reflection, including the opaque `Raw`, `Padding`,
//! and `Malformed` layers every protocol can fall back to.

mod model;
mod opaque;
mod reflection;

pub use model::{FieldSchema, Id, Layer, Schema};
pub use opaque::{Malformed, Padding, Raw, parse_hex};
// Codecs outside core call `raw_layout` to describe an opaque `Raw` layer; it
// stays out of the documented API.
#[doc(hidden)]
pub use opaque::raw_layout;
pub(crate) use opaque::{MalformedCodec, PaddingCodec, RawCodec};
pub(crate) use reflection::reflective_layer;
#[doc(hidden)]
pub use reflection::{ReflectiveField, Refusal, reflect_get, reflect_set, reflect_set_bounded};
