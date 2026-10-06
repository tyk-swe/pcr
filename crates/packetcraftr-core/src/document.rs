// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

mod convert;
mod error;
mod parse;
pub mod payload;
pub mod port_catalog;
pub mod recipe;
mod types;
pub mod udp_profiles;

pub use error::Error;
pub use types::{
    DEFAULT_MAX_DOCUMENT_BYTES, DocumentLimits, Format, Layer, Limit, MAX_DOCUMENT_NESTING,
    PACKET_DOCUMENT_SCHEMA_V2, Packet,
};
