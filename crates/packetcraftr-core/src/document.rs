// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Versioned packet documents.

mod convert;
mod error;
mod parse;
mod types;

pub use error::Error;
pub use types::{
    DEFAULT_MAX_DOCUMENT_BYTES, DEFAULT_MAX_DOCUMENT_NESTING, DocumentLimits, Format, Layer, Limit,
    MAX_DOCUMENT_NESTING, PACKET_DOCUMENT_SCHEMA_V1, Packet,
};
