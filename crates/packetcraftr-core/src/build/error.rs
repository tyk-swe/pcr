// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use thiserror::Error;

use crate::codec::Error as CodecError;
use crate::layer::{FieldError, Id as ProtocolId};

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
    MissingCodec { index: usize, protocol: ProtocolId },
    #[error("layer {protocol} at index {index} violates its reflective schema: {source}")]
    InvalidLayer {
        index: usize,
        protocol: ProtocolId,
        #[source]
        source: FieldError,
    },
    #[error("layer {parent} cannot contain adjacent layer {child}")]
    UnboundLayers {
        parent: ProtocolId,
        child: ProtocolId,
    },
    #[error("failed to encode layer {protocol} at index {index}: {source}")]
    Codec {
        index: usize,
        protocol: ProtocolId,
        #[source]
        source: CodecError,
    },
    #[error("packet length arithmetic overflow")]
    LengthOverflow,
    #[error("could not allocate {requested} bytes for the packet buffer")]
    AllocationFailure { requested: usize },
    #[error("codec for layer {protocol} returned a different materialized layer {actual}")]
    MaterializedProtocolMismatch {
        protocol: ProtocolId,
        actual: ProtocolId,
    },
    #[error("codec for layer {protocol} returned an invalid byte layout")]
    InvalidCodecLayout { protocol: ProtocolId },
    #[error("padding layer at index {index} has invalid outside-layer boundary {outside_layer}")]
    InvalidPaddingBoundary { index: usize, outside_layer: usize },
    #[error("padding layer at index {index} has no enclosing link-layer frame")]
    PaddingWithoutLinkLayer { index: usize },
}
