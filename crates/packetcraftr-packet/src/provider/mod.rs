// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Runtime-neutral protocol provider and per-operation session boundary.

mod native;

use std::fmt;
use std::net::IpAddr;

use packetcraftr_model::{ProviderId, RegistrationOrigin};
use thiserror::Error;

use crate::Packet;
use crate::codec::{
    CodecError, DecodedLayerValue, EncodedLayer, NativeLayerDecodeContext, NativeLayerEncodeContext,
};
use crate::layer::{Layer, ValidatedFieldSet};
use crate::matcher::MatchResult;

pub use native::{NativeProtocolImplementation, NativeProtocolProvider, ProviderProtocolKey};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProviderMatch {
    pub result: MatchResult,
    pub responder: Option<IpAddr>,
}

#[derive(Clone, Debug, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum ProviderError {
    #[error("provider session could not start: {message}")]
    BeginSession { message: String },
    #[error("provider does not own protocol key {key}")]
    UnknownProtocolKey { key: ProviderProtocolKey },
    #[error("protocol key {key} is registered more than once")]
    DuplicateProtocolKey { key: ProviderProtocolKey },
}

/// Immutable factory for short-lived, non-shared protocol sessions.
pub trait ProtocolProvider: Send + Sync + fmt::Debug {
    fn provider_id(&self) -> &ProviderId;
    fn origin(&self) -> &RegistrationOrigin;
    fn begin_session(&self) -> Result<Box<dyn ProtocolSession>, ProviderError>;
}

/// One non-concurrent provider instance for a single packet operation.
pub trait ProtocolSession: fmt::Debug {
    fn construct(
        &mut self,
        key: &ProviderProtocolKey,
        fields: &ValidatedFieldSet,
    ) -> Result<Box<dyn Layer>, CodecError>;

    fn encode(
        &mut self,
        key: &ProviderProtocolKey,
        layer: &dyn Layer,
        payload: &[u8],
        context: &NativeLayerEncodeContext<'_>,
    ) -> Result<EncodedLayer, CodecError>;

    fn decode(
        &mut self,
        key: &ProviderProtocolKey,
        input: &[u8],
        context: &NativeLayerDecodeContext,
    ) -> Result<DecodedLayerValue, CodecError>;

    fn match_response(
        &mut self,
        key: &ProviderProtocolKey,
        request: &Packet,
        response: &Packet,
    ) -> Result<Option<ProviderMatch>, CodecError>;
}
