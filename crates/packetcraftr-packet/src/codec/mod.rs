// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Extension contract for packet codecs.

mod contract;

#[doc(hidden)]
pub use contract::{
    CodecError, DecodedLayerValue, EncodedLayer, LayerCodec, LayerDecodeContext, LayerEncodeContext,
};
pub use contract::{
    CodecError as Error, DecodedLayerValue as Decoded, EncodedLayer as Encoded,
    LayerCodec as Codec, LayerDecodeContext as DecodeContext, LayerEncodeContext as EncodeContext,
    NetworkEnvelope,
};
