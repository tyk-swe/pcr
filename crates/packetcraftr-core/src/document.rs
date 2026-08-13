// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Versioned packet documents.

mod convert;
mod error;
mod parse;
mod serialize;
mod types;
mod validation;
mod visitor;

pub use error::DocumentError as Error;
pub use types::{
    DEFAULT_MAX_DOCUMENT_BYTES, DEFAULT_MAX_DOCUMENT_NESTING, DocumentFormat as Format,
    LayerDocument as Layer, MAX_DOCUMENT_NESTING, PACKET_DOCUMENT_SCHEMA_V1,
    PacketDocument as Packet,
};
