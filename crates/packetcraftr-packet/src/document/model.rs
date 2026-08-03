// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

mod convert;
mod error;
mod parse;
mod serialize;
mod types;
mod validation;
mod visitor;

#[cfg(test)]
mod tests;

pub use error::DocumentError;
pub use types::{
    DEFAULT_MAX_DOCUMENT_BYTES, DEFAULT_MAX_DOCUMENT_NESTING, DocumentFormat, LayerDocument,
    MAX_DOCUMENT_NESTING, PACKET_DOCUMENT_SCHEMA_V1, PacketDocument,
};
