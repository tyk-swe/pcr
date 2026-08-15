// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use thiserror::Error;

use crate::codec::CodecError;

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum DocumentError {
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
        source: CodecError,
    },
    #[error("could not serialize {format} packet document: {message}")]
    Serialize {
        format: &'static str,
        message: String,
    },
}
