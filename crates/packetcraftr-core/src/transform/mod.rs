// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Explicit, bounded transformations of complete packet bytes.

mod fragment;
mod rewrite;
pub use fragment::{FragmentOptions, fragment};
pub use rewrite::{HeaderRewrite, RewriteLimits, VlanTag, rewrite};

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
}

impl Classified for Error {
    fn classification(&self) -> Classification {
        match self {
            Self::Frame(source) => source.classification(),
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
        }
    }
}
