// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use thiserror::Error;

use super::super::layer::ProtocolId;

/// Why a display filter could not be compiled.
///
/// Every variant is a compile-time failure. Evaluation itself cannot fail: a
/// compiled filter either matches a packet or does not.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum FilterError {
    #[error("display filter is empty")]
    Empty,
    #[error("display filter has {actual} bytes, exceeding limit {limit}")]
    SizeLimit { actual: usize, limit: usize },
    #[error("display filter nesting exceeds configured limit {limit}")]
    NestingLimit { limit: usize },
    #[error("display filter nesting limit {value} exceeds stable maximum {maximum}")]
    InvalidNestingLimit { value: usize, maximum: usize },
    #[error("display filter term limit {value} exceeds stable maximum {maximum}")]
    InvalidTermLimit { value: usize, maximum: usize },
    #[error("display filter has more than {limit} terms")]
    TermLimit { limit: usize },
    #[error("display filter set has more than {limit} members")]
    SetMemberLimit { limit: usize },
    #[error("display filter set-member limit {value} exceeds stable maximum {maximum}")]
    InvalidSetMemberLimit { value: usize, maximum: usize },
    #[error("display filter syntax error at byte {offset}: {message}")]
    Syntax { offset: usize, message: String },
    #[error("unknown display filter field {path} at byte {offset}")]
    UnknownField { offset: usize, path: String },
    #[error("field {path} at byte {offset} is not a byte sequence, so it cannot be sliced")]
    UnsliceableField { offset: usize, path: String },
    #[error("field {path} at byte {offset} holds {kind}, which cannot be compared to {literal}")]
    IncompatibleLiteral {
        offset: usize,
        path: String,
        kind: &'static str,
        literal: String,
    },
    #[error(
        "field {path} at byte {offset} is compared to prefix {literal}, \
         which only `==` and `!=` can test"
    )]
    OrderedPrefixComparison {
        offset: usize,
        path: String,
        literal: String,
    },
    #[error("protocol {protocol} has no reflective schema, so {path} cannot be resolved")]
    UnresolvableProtocol { path: String, protocol: ProtocolId },
}
