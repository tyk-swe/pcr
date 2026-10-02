// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::error::{Classification, Classified, Kind};

mod codec;
mod model;
mod reflection;

pub use codec::{BodyDecoder, Progress, parse_head};
pub(crate) use codec::{HttpCodec, token};
pub use model::{Body, Head, Header, Http, StartLine};

pub const MAX_HEADER_BYTES: usize = 65_536;
pub const MAX_HEADERS: usize = 256;
pub const MAX_START_LINE: usize = 8192;

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    #[error("HTTP/1 {0}")]
    Invalid(&'static str),
    #[error("HTTP/1 exceeds its {0} limit")]
    Limit(Limit),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Limit {
    StartLine,
    HeaderBytes,
    HeaderCount,
    ChunkLine,
    BodyBytes,
    TrailerBytes,
}

impl std::fmt::Display for Limit {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::StartLine => "start line",
            Self::HeaderBytes => "header bytes",
            Self::HeaderCount => "header count",
            Self::ChunkLine => "chunk or trailer line",
            Self::BodyBytes => "body bytes",
            Self::TrailerBytes => "trailer bytes",
        })
    }
}

impl Classified for Error {
    fn classification(&self) -> Classification {
        match self {
            Self::Invalid(_) => Classification::new("packet.http", Kind::Packet, None),
            Self::Limit(_) => Classification::new("policy.http_limit", Kind::Policy, None),
        }
    }
}
