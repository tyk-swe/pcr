// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Versioned packet documents, and the packet recipes that are either a
//! document or a layer expression.

mod convert;
mod error;
mod parse;
mod recipe;
mod types;

pub use error::Error;
pub use recipe::{PayloadError, PayloadTarget, RecipeError, parse_recipe};
pub use types::{
    DEFAULT_MAX_DOCUMENT_BYTES, DocumentLimits, Format, Layer, Limit, MAX_DOCUMENT_NESTING,
    PACKET_DOCUMENT_SCHEMA_V2, Packet,
};
