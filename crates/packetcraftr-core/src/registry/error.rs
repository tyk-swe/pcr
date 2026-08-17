// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use thiserror::Error;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    #[error("protocol codec {protocol} is already registered")]
    DuplicateProtocol { protocol: crate::layer::Id },
    #[error("protocol alias {alias} is already registered for {existing}")]
    DuplicateAlias {
        alias: String,
        existing: crate::layer::Id,
    },
    #[error("link type {link_type} already has a root binding")]
    DuplicateLinkType { link_type: u32 },
    #[error(
        "binding conflict for parent {parent}, discriminator {discriminator}, priority {priority}"
    )]
    BindingConflict {
        parent: crate::layer::Id,
        discriminator: u64,
        priority: i32,
    },
    #[error("response matcher for {protocol} is already registered")]
    DuplicateMatcher { protocol: crate::layer::Id },
    #[error("binding references unregistered protocol {protocol}")]
    UnknownProtocol { protocol: crate::layer::Id },
    #[error("filter field path {path} is already registered for {existing}")]
    DuplicateFilterField {
        path: String,
        existing: crate::layer::Id,
    },
    #[error("filter field path {path} names field {field}, absent from layer {protocol}")]
    UnknownFilterField {
        path: String,
        protocol: crate::layer::Id,
        field: String,
    },
    #[error("filter field path {path} is not usable: {reason}")]
    InvalidFilterField { path: String, reason: String },
}
