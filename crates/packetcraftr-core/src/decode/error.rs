// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use thiserror::Error;

use crate::frame::Error as FrameError;
use crate::layer::{FieldError, Id as ProtocolId};

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    #[error("captured packet size {actual} exceeds configured limit {limit}")]
    PacketSizeLimit { actual: usize, limit: usize },
    #[error("decoded layer count reached configured limit {limit}")]
    LayerLimit { limit: usize },
    #[error("no codec is registered for root protocol {protocol}")]
    MissingRootCodec { protocol: ProtocolId },
    #[error("codec for {protocol} returned an invalid cursor range")]
    InvalidCodecCursor { protocol: ProtocolId },
    #[error("codec for {protocol} returned an invalid field layout")]
    InvalidCodecLayout { protocol: ProtocolId },
    #[error("codec for {protocol} returned layer {actual}")]
    CodecLayerMismatch {
        protocol: ProtocolId,
        actual: ProtocolId,
    },
    #[error("codec for {protocol} returned a layer that violates its reflective schema: {source}")]
    InvalidLayer {
        protocol: ProtocolId,
        #[source]
        source: FieldError,
    },
    #[error("invalid frame: {0}")]
    InvalidFrame(#[from] FrameError),
}
