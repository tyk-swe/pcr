// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

mod model;
mod opaque;
mod reflection;
pub mod selector;

pub use model::{FieldSchema, Id, Layer, Schema};
pub use opaque::{Malformed, Padding, Raw, parse_hex};
pub(crate) use opaque::{MalformedCodec, PaddingCodec, RawCodec};
pub(crate) use reflection::reflective_layer;
pub use reflection::{ReflectiveField, Refusal, reflect_get, reflect_set, reflect_set_bounded};
