// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use thiserror::Error;

use super::super::field::FieldKind;

/// Why a display filter could not be compiled.
///
/// Every variant is a compile-time failure. Evaluation cannot fail: a compiled
/// filter either matches a packet or does not.
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
    #[error("filter syntax error at byte {offset}: {message}")]
    Syntax { offset: usize, message: String },
    #[error(
        "unknown protocol {name} at byte {offset}; run `packetcraftr protocols` for the registered names"
    )]
    UnknownProtocol { offset: usize, name: String },
    #[error("protocol {protocol} has no field {field} at byte {offset}; it exposes {}", format_names(.available))]
    UnknownField {
        offset: usize,
        protocol: String,
        field: String,
        available: Vec<String>,
    },
    #[error("protocol {protocol} exposes no reflective fields at byte {offset}")]
    UnreflectiveProtocol { offset: usize, protocol: String },
    #[error("{protocol}.{field} is {} and cannot be compared with {literal} at byte {offset}", kind_name(*.kind))]
    TypeMismatch {
        offset: usize,
        protocol: String,
        field: String,
        kind: FieldKind,
        literal: String,
    },
    #[error(
        "{protocol}.{field} is {} and supports only == and != at byte {offset}", kind_name(*.kind)
    )]
    UnorderedField {
        offset: usize,
        protocol: String,
        field: String,
        kind: FieldKind,
    },
    #[error("{protocol}.{field} is a list and cannot be filtered at byte {offset}")]
    UnfilterableField {
        offset: usize,
        protocol: String,
        field: String,
    },
}

fn format_names(names: &[String]) -> String {
    if names.is_empty() {
        return "no fields".to_owned();
    }
    names.join(", ")
}

/// Stable spelling used in messages, matching the `protocols` command.
pub(super) fn kind_name(kind: FieldKind) -> &'static str {
    match kind {
        FieldKind::Bool => "bool",
        FieldKind::Unsigned => "unsigned",
        FieldKind::Signed => "signed",
        FieldKind::Text => "text",
        FieldKind::Bytes => "bytes",
        FieldKind::Ipv4 => "ipv4",
        FieldKind::Ipv6 => "ipv6",
        FieldKind::Mac => "mac",
        FieldKind::List => "list",
        // `FieldKind` is non-exhaustive so external codecs can add kinds.
        #[allow(unreachable_patterns)]
        _ => "an unsupported kind",
    }
}
