// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use thiserror::Error;

use crate::error::{Classification, Classified, Kind};

use super::types::{DocumentLimits, Limit};

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    #[error("packet document has {actual} bytes, exceeding limit {limit}")]
    SizeLimit { actual: usize, limit: usize },
    #[error("could not parse {format} packet document: {message}")]
    Parse {
        format: &'static str,
        message: String,
    },
    #[error("unsupported packet document schema {actual}; expected {expected}")]
    Schema {
        actual: String,
        expected: &'static str,
    },
    #[error("packet document has more than {limit} layers")]
    LayerLimit { limit: usize },
    #[error("packet document field nesting exceeds configured limit {limit}")]
    NestingLimit { limit: usize },
    #[error("packet document exceeds configured limit {limit}={maximum}")]
    ResourceLimit { limit: Limit, maximum: usize },
    #[error("packet document limit {field}={value} exceeds stable maximum {maximum}")]
    InvalidLimit {
        field: &'static str,
        value: usize,
        maximum: usize,
    },
    #[error("unknown protocol {protocol} at layer {layer}")]
    UnknownProtocol { layer: usize, protocol: String },
    #[error("invalid {protocol} layer at index {layer}: {source}")]
    Layer {
        layer: usize,
        protocol: String,
        #[source]
        source: crate::codec::Error,
    },
    #[error("invalid {protocol} layer at index {layer}: {source}")]
    Field {
        layer: usize,
        protocol: String,
        #[source]
        source: crate::layer::FieldError,
    },
}

impl Error {
    /// The configured limit this error reports, if it is a resource rejection.
    #[must_use]
    pub const fn limit(&self) -> Option<Limit> {
        match self {
            Self::SizeLimit { .. } => Some(Limit::InputBytes),
            Self::LayerLimit { .. } => Some(Limit::Layers),
            Self::NestingLimit { .. } => Some(Limit::Nesting),
            Self::ResourceLimit { limit, .. } => Some(*limit),
            _ => None,
        }
    }

    pub(super) fn exceeded(limit: Limit, limits: &DocumentLimits) -> Self {
        let maximum = limits.maximum(limit);
        match limit {
            Limit::Layers => Self::LayerLimit { limit: maximum },
            Limit::Nesting => Self::NestingLimit { limit: maximum },
            Limit::InputBytes
            | Limit::FieldsPerLayer
            | Limit::TotalNodes
            | Limit::ListItems
            | Limit::TotalListItems
            | Limit::ProtocolNameBytes
            | Limit::FieldNameBytes
            | Limit::TextBytes
            | Limit::ByteValueBytes
            | Limit::TotalPayloadBytes => Self::ResourceLimit { limit, maximum },
        }
    }
}

impl Classified for Error {
    fn classification(&self) -> Classification {
        match self {
            Self::SizeLimit { .. }
            | Self::LayerLimit { .. }
            | Self::NestingLimit { .. }
            | Self::ResourceLimit { .. }
            | Self::InvalidLimit { .. } => Classification::new(
                "cli.document_limit",
                Kind::Cli,
                Some(
                    "shrink the packet document to stay inside its finite byte, node, and nesting bounds",
                ),
            ),
            Self::Parse { .. } => Classification::new(
                "cli.document_syntax",
                Kind::Cli,
                Some("repair the packet document so it parses as well-formed JSON or YAML"),
            ),
            Self::Schema { .. } => Classification::new(
                "cli.document_schema",
                Kind::Cli,
                Some("declare the packet document schema this build supports"),
            ),
            Self::UnknownProtocol { .. } => Classification::new(
                "cli.document_protocol",
                Kind::Cli,
                Some("run `packetcraftr protocols` to list the protocol names the registry binds"),
            ),
            Self::Layer { .. } | Self::Field { .. } => Classification::new(
                "cli.document_field",
                Kind::Cli,
                Some("correct the layer's field names and values against its reflective schema"),
            ),
        }
    }
}
