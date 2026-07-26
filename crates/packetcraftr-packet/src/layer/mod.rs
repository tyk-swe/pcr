// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Packet layer models and reflection.

mod model;
mod reflection;

pub use packetcraftr_model::ProtocolId;
pub use packetcraftr_model::ProtocolId as Id;

pub use model::{FieldError, FieldSchema, LayerSchema, MalformedLayer};
pub use model::{Layer, LayerSchema as Schema, MalformedLayer as Malformed, Padding, Raw};
pub use model::{malformed_layout, padding_layout, raw_layout};
pub use reflection::{reflect_get, reflect_set, reflective_layer};
