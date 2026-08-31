// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use thiserror::Error;

use crate::error::{Classification, Classified, Kind};
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
            Self::EmptyPacket => Classification::new(
                "packet.empty",
                Kind::Packet,
                Some("supply at least one layer before building"),
            ),
            Self::LayerLimit { .. }
            | Self::PacketSizeLimit { .. }
            | Self::AllocationFailure { .. } => Classification::new(
                "policy.build_resource_limit",
                Kind::Policy,
                Some(
                    "shrink the packet or deliberately raise the finite build layer and byte budget",
                ),
            ),
            Self::MissingCodec { .. } => Classification::new(
                "packet.missing_codec",
                Kind::Packet,
                Some("name a protocol the registry binds, or register a codec for it"),
            ),
            Self::InvalidLayer { .. } => Classification::new(
                "packet.invalid_layer",
                Kind::Packet,
                Some("supply every field the layer's reflective schema declares required"),
            ),
            Self::UnboundLayers { .. } => Classification::new(
                "packet.unbound_layers",
                Kind::Packet,
                Some("order the layers so each parent can carry the next, or build permissively"),
            ),
            Self::Codec { .. } => Classification::new(
                "packet.codec",
                Kind::Packet,
                Some("correct the layer field values the codec refused to encode"),
            ),
            Self::LengthOverflow => Classification::new(
                "packet.length_overflow",
                Kind::Packet,
                Some("shrink the packet so its byte offsets stay representable"),
            ),
            Self::MaterializedProtocolMismatch { .. } | Self::InvalidCodecLayout { .. } => {
                Classification::new(
                    "internal.codec_contract",
                    Kind::Internal,
                    Some(
                        "report the codec that returned a protocol or byte layout its own contract forbids",
                    ),
                )
            }
            Self::InvalidPaddingBoundary { .. } | Self::PaddingWithoutLinkLayer { .. } => {
                Classification::new(
                    "packet.padding_boundary",
                    Kind::Packet,
                    Some(
                        "attach padding to an enclosing link-layer frame with a valid outside-layer index",
                    ),
                )
            }
        }
    }

    /// Walked from the retained `#[source]` chain rather than hand-written.
    fn causes(&self) -> Vec<String> {
        crate::error::source_chain(self)
    }
}
