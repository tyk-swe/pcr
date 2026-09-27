// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Cleartext HTTP/1 header dissection and bounded streaming body framing.
//!
//! The [`Http`] layer and its head live in `model`, head parsing, body
//! framing, and the layer codec in `codec`, and field reflection in
//! `reflection`. Every wire API returns [`Error`].

use crate::error::{Classification, Classified, Kind};

mod codec;
mod model;
mod reflection;

pub(crate) use codec::HttpCodec;
pub use codec::{BodyDecoder, Progress, parse_head};
pub use model::{Body, Head, Header, Http, StartLine};

pub const MAX_HEADER_BYTES: usize = 65_536;
pub const MAX_HEADERS: usize = 256;
pub const MAX_START_LINE: usize = 8192;

/// An HTTP/1 head or body framing that breaks a wire rule or a bound.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    #[error("HTTP/1 {0}")]
    Invalid(&'static str),
    #[error("HTTP/1 exceeds its {0} limit")]
    Limit(Limit),
}
/// The HTTP/1 bound an [`Error::Limit`] exceeds.
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
