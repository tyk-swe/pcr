// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use thiserror::Error;

use crate::layer::Id as ProtocolId;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    #[error("protocol codec {protocol} is already registered")]
    DuplicateProtocol { protocol: ProtocolId },
    #[error("protocol alias {alias} is already registered for {existing}")]
    DuplicateAlias { alias: String, existing: ProtocolId },
    #[error("link type {link_type} already has a root binding")]
    DuplicateLinkType { link_type: u32 },
    #[error(
        "binding conflict for parent {parent}, discriminator {discriminator}, priority {priority}"
    )]
    BindingConflict {
        parent: ProtocolId,
        discriminator: u64,
        priority: i32,
    },
    #[error("response matcher for {protocol} is already registered")]
    DuplicateMatcher { protocol: ProtocolId },
    #[error("binding references unregistered protocol {protocol}")]
    UnknownProtocol { protocol: ProtocolId },
    #[error("filter field path {path} is already registered for {existing}")]
    DuplicateFilterField { path: String, existing: ProtocolId },
    #[error("filter field path {path} names field {field}, absent from layer {protocol}")]
    UnknownFilterField {
        path: String,
        protocol: ProtocolId,
        field: String,
    },
    #[error("filter field path {path} is not usable: {reason}")]
    InvalidFilterField { path: String, reason: String },
}
