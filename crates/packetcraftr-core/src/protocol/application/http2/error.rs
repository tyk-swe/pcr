// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::error::{Classification, Classified, Kind};

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    #[error("HTTP/2 {0}")]
    Invalid(&'static str),
    #[error("HTTP/2 exceeds its {0} limit")]
    Limit(Limit),
    #[error("HTTP/2 header compression {0}")]
    Compression(&'static str),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Limit {
    FrameBytes,
    BlockBytes,
    HeaderBytes,
    HeaderCount,
    TableBytes,
    OriginBytes,
}

impl std::fmt::Display for Limit {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::FrameBytes => "frame payload bytes",
            Self::BlockBytes => "compressed block bytes",
            Self::HeaderBytes => "decoded header bytes",
            Self::HeaderCount => "header count",
            Self::TableBytes => "dynamic table bytes",
            Self::OriginBytes => "field origin metadata",
        })
    }
}

impl Classified for Error {
    fn classification(&self) -> Classification {
        match self {
            Self::Invalid(_) => Classification::new("packet.http2", Kind::Packet, None),
            Self::Limit(_) => Classification::new("policy.http2_limit", Kind::Policy, None),
            Self::Compression(_) => {
                Classification::new("packet.http2_compression", Kind::Packet, None)
            }
        }
    }
}
