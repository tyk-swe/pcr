// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Explicit, bounded transformations of complete packet bytes.

mod fields;
mod fragment;
mod rewrite;
pub use fields::{
    ChangeOrigin, ChecksumMode, FieldAssignment, FieldChange, FieldEdit, FieldEditOutcome,
    FieldEdits, MAX_FIELD_ASSIGNMENTS,
};
pub use fragment::{FragmentOptions, fragment};
pub use rewrite::{HeaderRewrite, RewriteLimits, VlanRewrite, rewrite};

use crate::error::{Classification, Classified, Kind};

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    #[error("invalid packet transform input: {0}")]
    Invalid(&'static str),
    #[error("unsupported packet transform: {0}")]
    Unsupported(&'static str),
    #[error("packet transform exceeds {field}={limit}")]
    Limit { field: &'static str, limit: usize },
    #[error(transparent)]
    Frame(#[from] crate::frame::Error),
    #[error(transparent)]
    Decode(#[from] crate::decode::Error),
    #[error("packet transform checksum failed: {0}")]
    Checksum(#[source] crate::codec::Error),
}

impl Classified for Error {
    fn classification(&self) -> Classification {
        match self {
            Self::Frame(source) => source.classification(),
            Self::Decode(source) => source.classification(),
            Self::Invalid(_) => Classification::new(
                "packet.transform_input",
                Kind::Packet,
                Some("supply a complete supported datagram"),
            ),
            Self::Unsupported(_) => Classification::new(
                "packet.transform_unsupported",
                Kind::Packet,
                Some("inspect the documented transform boundaries"),
            ),
            Self::Limit { .. } => Classification::new(
                "policy.transform_limit",
                Kind::Policy,
                Some("raise a finite transform limit or reduce the input"),
            ),
            Self::Checksum(_) => Classification::new(
                "packet.transform_checksum",
                Kind::Packet,
                Some("supply a complete datagram the checksum can cover"),
            ),
        }
    }
}

impl From<crate::protocol::network::envelope::WalkError> for Error {
    fn from(error: crate::protocol::network::envelope::WalkError) -> Self {
        use crate::protocol::network::envelope::WalkError;
        match error {
            WalkError::DepthExceeded { header, limit } => Self::Limit {
                field: header,
                limit,
            },
            WalkError::Truncated(_) => Self::Invalid("truncated header walk"),
            WalkError::InvalidLength(_) => Self::Invalid("invalid header walk length"),
        }
    }
}

impl From<crate::protocol::network::envelope::CoverageError> for Error {
    fn from(error: crate::protocol::network::envelope::CoverageError) -> Self {
        use crate::protocol::network::envelope::{ChecksumRefusal, CoverageError};
        match error {
            CoverageError::Walk(walk) => walk.into(),
            CoverageError::Invalid(message) => Self::Invalid(message),
            CoverageError::Refused(refusal) => Self::Unsupported(match refusal {
                ChecksumRefusal::FragmentedDatagram => {
                    "transport checksum repair needs a complete datagram"
                }
                ChecksumRefusal::Ipv4SourceRoute => {
                    "IPv4 source routing changes checksum destinations"
                }
                ChecksumRefusal::Ipv6RoutingHeader => {
                    "IPv6 routing headers change checksum destinations"
                }
                ChecksumRefusal::Ipv6HomeAddress => {
                    "IPv6 Home Address option changes checksum sources"
                }
                ChecksumRefusal::AuthenticatedHeader => {
                    "authenticated IPv6 header cannot be repaired"
                }
            }),
        }
    }
}
