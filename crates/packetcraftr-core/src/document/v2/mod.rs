// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Version 2 of the PacketcraftR packet document format (`packetcraftr.packet/v2`).

pub mod emit;
pub mod model;
pub mod parse;
pub mod types;
pub mod upgrade;

pub use emit::Minimized;
pub use types::{Document, Layer, PACKET_DOCUMENT_SCHEMA_V2, Value, field_path};
