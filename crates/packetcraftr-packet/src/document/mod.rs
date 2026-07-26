// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Versioned packet documents.

mod model;

pub use model::PacketDocument;
pub use model::{
    DEFAULT_MAX_DOCUMENT_BYTES, DEFAULT_MAX_DOCUMENT_NESTING, DocumentError as Error,
    DocumentFormat as Format, LayerDocument as Layer, MAX_DOCUMENT_NESTING,
    PACKET_DOCUMENT_SCHEMA_V1, PacketDocument as Packet,
};
