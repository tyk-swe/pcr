// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Versioned packet documents, and the packet recipes that are either a
//! document or a layer expression.
//!
//! Recipes ([`recipe`]) and the payload fields a recipe leaves for outside
//! bytes ([`payload`]) are sub-domains with their own `Error`.

mod convert;
mod error;
mod parse;
pub mod payload;
pub mod recipe;
mod types;

pub use error::Error;
pub use types::{
    DEFAULT_MAX_DOCUMENT_BYTES, DocumentLimits, Format, Layer, Limit, MAX_DOCUMENT_NESTING,
    PACKET_DOCUMENT_SCHEMA_V2, Packet,
};
