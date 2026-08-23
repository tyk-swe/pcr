// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use thiserror::Error;

use crate::error::{Classification, Classified};
use crate::layer::FieldError;

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    #[error("cannot build an empty packet")]
    EmptyPacket,
    #[error("packet has {actual} layers, exceeding configured limit {limit}")]
    LayerLimit { actual: usize, limit: usize },
    #[error("packet size {actual} exceeds configured limit {limit}")]
    PacketSizeLimit { actual: usize, limit: usize },
    #[error("no codec is registered for layer {protocol} at index {index}")]
    MissingCodec {
        index: usize,
        protocol: crate::layer::Id,
    },
    #[error("layer {protocol} at index {index} violates its reflective schema: {source}")]
    InvalidLayer {
        index: usize,
        protocol: crate::layer::Id,
        #[source]
        source: FieldError,
    },
    #[error("layer {parent} cannot contain adjacent layer {child}")]
    UnboundLayers {
        parent: crate::layer::Id,
        child: crate::layer::Id,
    },
    #[error("failed to encode layer {protocol} at index {index}: {source}")]
    Codec {
        index: usize,
        protocol: crate::layer::Id,
        #[source]
        source: crate::codec::Error,
    },
    #[error("packet length arithmetic overflow")]
    LengthOverflow,
    #[error("could not allocate {requested} bytes for the packet buffer")]
    AllocationFailure { requested: usize },
    #[error("codec for layer {protocol} returned a different materialized layer {actual}")]
    MaterializedProtocolMismatch {
        protocol: crate::layer::Id,
        actual: crate::layer::Id,
    },
    #[error("codec for layer {protocol} returned an invalid byte layout")]
    InvalidCodecLayout { protocol: crate::layer::Id },
    #[error("padding layer at index {index} has invalid outside-layer boundary {outside_layer}")]
    InvalidPaddingBoundary { index: usize, outside_layer: usize },
    #[error("padding layer at index {index} has no enclosing link-layer frame")]
    PaddingWithoutLinkLayer { index: usize },
}

impl Classified for Error {
    fn classification(&self) -> Classification {
        match self {
            Self::LayerLimit { .. }
            | Self::PacketSizeLimit { .. }
            | Self::AllocationFailure { .. }
            | Self::LengthOverflow => Classification::new(
                "packet.build_limit",
                Some("reduce the packet or raise the finite build limit"),
            ),
            Self::EmptyPacket
            | Self::UnboundLayers { .. }
            | Self::InvalidLayer { .. }
            | Self::Codec { .. }
            | Self::InvalidPaddingBoundary { .. }
            | Self::PaddingWithoutLinkLayer { .. } => Classification::new(
                "packet.build",
                Some("correct the packet layers and fields before building"),
            ),
            Self::MissingCodec { .. } => Classification::new(
                "packet.unknown_protocol",
                Some("register a codec for every packet layer before building"),
            ),
            Self::MaterializedProtocolMismatch { .. } | Self::InvalidCodecLayout { .. } => {
                Classification::new(
                    "internal.codec_contract",
                    Some("repair the codec to honor the layer encoding contract"),
                )
            }
        }
    }
}
