// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Byte-level packet layouts.

mod model;

pub use model::{
    ByteRange as Range, FieldLayout as Field, LayerLayout as Layer, PacketLayout as Packet,
};
#[doc(hidden)]
pub use model::{ByteRange, FieldLayout, LayerLayout, PacketLayout};
