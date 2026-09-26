// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::error::{Classification, Classified, Kind};
use crate::layer::Id;

/// Why a reflective field read, edit, or path was refused.
#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    #[error("layer {protocol} has no field named {field}")]
    UnknownField { protocol: Id, field: String },
    #[error("field {field} on layer {protocol} expected {expected}")]
    WrongType {
        protocol: Id,
        field: String,
        expected: &'static str,
    },
    #[error("field {field} on layer {protocol} is outside the allowed range")]
    OutOfRange { protocol: Id, field: String },
    #[error("field {field} on layer {protocol} cannot be edited reflectively")]
    ReadOnly { protocol: Id, field: String },
    #[error("required field {field} is absent from layer {protocol} after defaults")]
    MissingRequired { protocol: Id, field: String },
    /// The text is not a bounded reflective [`Path`](super::Path).
    #[error("invalid reflective field path {path:?}")]
    InvalidPath { path: String },
}

impl Classified for Error {
    fn classification(&self) -> Classification {
        Classification::new(
            "packet.invalid_layer",
            Kind::Packet,
            Some("correct the layer's field names and values against its reflective schema"),
        )
    }
}
