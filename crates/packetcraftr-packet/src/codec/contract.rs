// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::BTreeMap;
use std::fmt;
use std::net::IpAddr;

use thiserror::Error;

use super::super::Packet;
use super::super::build::{BuildContext, BuildMode};
use super::super::diagnostic::Diagnostic;
use super::super::layer::{FieldError, Layer, ProtocolId, ValidatedFieldSet};
use super::super::layout::FieldLayout;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Discriminator(pub u64);

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum CodecError {
    #[error("codec expected layer {expected}, got {actual}")]
    WrongLayer {
        expected: ProtocolId,
        actual: ProtocolId,
    },
    #[error("truncated {protocol} layer: need at least {needed} bytes, got {available}")]
    Truncated {
        protocol: ProtocolId,
        needed: usize,
        available: usize,
    },
    #[error("invalid {protocol} layer: {message}")]
    Invalid {
        protocol: ProtocolId,
        message: String,
    },
    #[error("unsupported {protocol} construct: {message}")]
    Unsupported {
        protocol: ProtocolId,
        message: String,
    },
    #[error("packet length arithmetic overflow while processing {protocol}")]
    LengthOverflow { protocol: ProtocolId },
    #[error(transparent)]
    Field(#[from] FieldError),
}

/// Bounded parent-local decode bindings exposed as resolved encode facts.
#[derive(Clone, Copy)]
pub struct ParentBindingFacts<'a> {
    bindings: Option<&'a BTreeMap<Discriminator, ProtocolId>>,
}

impl<'a> ParentBindingFacts<'a> {
    pub(crate) const fn new(bindings: &'a BTreeMap<Discriminator, ProtocolId>) -> Self {
        Self {
            bindings: Some(bindings),
        }
    }

    /// Empty resolved facts for a parent with no registered decode bindings.
    pub const fn empty() -> Self {
        Self { bindings: None }
    }

    pub fn child_for(&self, discriminator: Discriminator) -> Option<&'a ProtocolId> {
        self.bindings?.get(&discriminator)
    }
}

impl fmt::Debug for ParentBindingFacts<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ParentBindingFacts")
            .field("binding_count", &self.bindings.map_or(0, BTreeMap::len))
            .finish()
    }
}

/// Host-resolved facts for one trusted native encode call.
///
/// The complete catalog is intentionally absent. A codec receives only packet
/// state and the child/binding facts already selected by the host.
///
/// ```compile_fail
/// use packetcraftr_packet::codec::NativeLayerEncodeContext;
///
/// fn inspect_catalog(context: &NativeLayerEncodeContext<'_>) {
///     let _ = &context.catalog;
/// }
/// ```
pub struct NativeLayerEncodeContext<'a> {
    pub packet: &'a Packet,
    pub index: usize,
    pub build_context: &'a BuildContext,
    pub mode: BuildMode,
    pub child: Option<&'a dyn Layer>,
    pub child_protocol: Option<&'a ProtocolId>,
    pub canonical_child_discriminator: Option<Discriminator>,
    pub parent_bindings: ParentBindingFacts<'a>,
    /// Maximum additional bytes this layer may contribute without exceeding
    /// the operation's configured packet-size limit.
    pub remaining_packet_bytes: usize,
}

pub struct EncodedLayer {
    pub prefix: Vec<u8>,
    pub suffix: Vec<u8>,
    pub materialized: Box<dyn Layer>,
    pub fields: Vec<FieldLayout>,
    pub diagnostics: Vec<Diagnostic>,
}

impl EncodedLayer {
    pub fn header(prefix: Vec<u8>, materialized: Box<dyn Layer>) -> Self {
        Self {
            prefix,
            suffix: Vec::new(),
            materialized,
            fields: Vec::new(),
            diagnostics: Vec::new(),
        }
    }
}

/// Bounded packet facts for one trusted native decode call.
pub struct NativeLayerDecodeContext {
    pub layer_index: usize,
    pub absolute_offset: usize,
    pub verify_checksums: bool,
    /// Whether bytes outside an IP-declared length may be link-layer padding.
    pub allow_trailing_padding: bool,
    /// Network pseudo-header context established by an enclosing IP codec.
    pub network: Option<NetworkEnvelope>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NetworkEnvelope {
    pub source: IpAddr,
    pub destination: IpAddr,
}

pub struct DecodedLayerValue {
    pub layer: Box<dyn Layer>,
    pub consumed: usize,
    pub payload_offset: usize,
    pub payload_len: usize,
    pub next: Vec<Discriminator>,
    pub fields: Vec<FieldLayout>,
    pub diagnostics: Vec<Diagnostic>,
    pub stop: bool,
    /// New pseudo-header context to carry into child decoders.
    pub network: Option<NetworkEnvelope>,
}

impl DecodedLayerValue {
    pub fn terminal(layer: Box<dyn Layer>, consumed: usize) -> Self {
        Self {
            layer,
            consumed,
            payload_offset: consumed,
            payload_len: 0,
            next: Vec::new(),
            fields: Vec::new(),
            diagnostics: Vec::new(),
            stop: true,
            network: None,
        }
    }
}

/// Trusted in-process Rust implementation for one native protocol key.
///
/// Protocol identity, aliases, schema, accepted decode protocols, and
/// provenance live in catalog registration descriptors, not on the codec.
pub trait NativeLayerCodec: Send + Sync + fmt::Debug {
    fn encode(
        &self,
        layer: &dyn Layer,
        payload: &[u8],
        context: &NativeLayerEncodeContext<'_>,
    ) -> Result<EncodedLayer, CodecError>;

    fn decode(
        &self,
        input: &[u8],
        context: &NativeLayerDecodeContext,
    ) -> Result<DecodedLayerValue, CodecError>;

    fn make_layer(&self, fields: &ValidatedFieldSet) -> Result<Box<dyn Layer>, CodecError>;
}
