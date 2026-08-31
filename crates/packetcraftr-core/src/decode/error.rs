// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use thiserror::Error;

use crate::error::{Classification, Classified, Kind};
use crate::layer::FieldError;

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    #[error("captured packet size {actual} exceeds configured limit {limit}")]
    PacketSizeLimit { actual: usize, limit: usize },
    #[error("decoded layer count reached configured limit {limit}")]
    LayerLimit { limit: usize },
    #[error("no codec is registered for root protocol {protocol}")]
    MissingRootCodec { protocol: crate::layer::Id },
    #[error("codec for {protocol} returned an invalid cursor range")]
    InvalidCodecCursor { protocol: crate::layer::Id },
    #[error("codec for {protocol} returned an invalid field layout")]
    InvalidCodecLayout { protocol: crate::layer::Id },
    #[error("codec for {protocol} returned layer {actual}")]
    CodecLayerMismatch {
        protocol: crate::layer::Id,
        actual: crate::layer::Id,
    },
    #[error("codec for {protocol} returned a layer that violates its reflective schema: {source}")]
    InvalidLayer {
        protocol: crate::layer::Id,
        #[source]
        source: FieldError,
    },
    #[error("invalid frame: {0}")]
    InvalidFrame(#[from] crate::frame::Error),
}

impl Classified for Error {
    fn classification(&self) -> Classification {
        match self {
            Self::PacketSizeLimit { .. } | Self::LayerLimit { .. } => Classification::new(
                "policy.decode_resource_limit",
                Kind::Policy,
                Some(
                    "narrow the input or deliberately raise the finite per-frame byte and layer budget",
                ),
            ),
            Self::MissingRootCodec { .. } => Classification::new(
                "packet.missing_codec",
                Kind::Packet,
                Some("decode with a registry that binds the frame's capture link type"),
            ),
            Self::InvalidCodecCursor { .. }
            | Self::InvalidCodecLayout { .. }
            | Self::CodecLayerMismatch { .. }
            | Self::InvalidLayer { .. } => Classification::new(
                "internal.codec_contract",
                Kind::Internal,
                Some(
                    "report the codec that returned a cursor, layout, or layer its own contract forbids",
                ),
            ),
            Self::InvalidFrame(source) => source.classification(),
        }
    }

    /// Walked from the retained `#[source]` chain rather than hand-written.
    fn causes(&self) -> Vec<String> {
        crate::error::source_chain(self)
    }
}
