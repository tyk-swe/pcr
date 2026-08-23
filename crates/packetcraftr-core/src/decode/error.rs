// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use thiserror::Error;

use crate::error::{Classification, Classified};
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
                "packet.decode_limit",
                Some("reduce the frame or raise the finite decode limit"),
            ),
            Self::MissingRootCodec { .. } | Self::InvalidFrame(_) => Classification::new(
                "packet.decode",
                Some("repair the frame or register a root codec before decoding"),
            ),
            Self::InvalidCodecCursor { .. }
            | Self::InvalidCodecLayout { .. }
            | Self::CodecLayerMismatch { .. }
            | Self::InvalidLayer { .. } => Classification::new(
                "internal.codec_contract",
                Some("repair the codec to honor the layer decoding contract"),
            ),
        }
    }
}
