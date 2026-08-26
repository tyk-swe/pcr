// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Versioned packet documents.

mod convert;
mod error;
mod parse;
mod types;
pub mod v2;
mod visitor;

pub use error::{Error, deprecated_schema_diagnostic};
pub use types::{
    DEFAULT_MAX_DOCUMENT_BYTES, DEFAULT_MAX_DOCUMENT_NESTING, Format, Layer, MAX_DOCUMENT_NESTING,
    PACKET_DOCUMENT_SCHEMA_V1, Packet,
};
pub use v2::{Document, PACKET_DOCUMENT_SCHEMA_V2};
