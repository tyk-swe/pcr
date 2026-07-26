// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Trusted native codec contracts and host-neutral wire facts.

mod contract;

pub use contract::{
    CodecError, DecodedLayerValue, Discriminator, EncodedLayer, NativeLayerCodec,
    NativeLayerDecodeContext, NativeLayerEncodeContext, NetworkEnvelope, ParentBindingFacts,
};
