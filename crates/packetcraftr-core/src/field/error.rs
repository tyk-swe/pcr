// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::error::{Classification, Classified, Kind};
use crate::layer::Id;

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
    #[error("invalid reflective field path {path:?}")]
    InvalidPath { path: String },
}

impl Error {
    pub fn with_field_name(self, name: &str) -> Self {
        match self {
            Self::UnknownField { protocol, .. } => Self::UnknownField {
                protocol,
                field: name.to_owned(),
            },
            Self::WrongType {
                protocol, expected, ..
            } => Self::WrongType {
                protocol,
                field: name.to_owned(),
                expected,
            },
            Self::OutOfRange { protocol, .. } => Self::OutOfRange {
                protocol,
                field: name.to_owned(),
            },
            Self::ReadOnly { protocol, .. } => Self::ReadOnly {
                protocol,
                field: name.to_owned(),
            },
            Self::MissingRequired { protocol, .. } => Self::MissingRequired {
                protocol,
                field: name.to_owned(),
            },
            Self::InvalidPath { .. } => self,
        }
    }
}

impl Classified for Error {
    fn classification(&self) -> Classification {
        Classification::new(
            crate::error::Code::PacketInvalidLayer,
            Kind::Packet,
            Some("correct the layer's field names and values against its reflective schema"),
        )
    }
}
