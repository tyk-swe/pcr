// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Extension contract for packet codecs.

use std::collections::BTreeMap;
use std::fmt;
use std::net::IpAddr;

use thiserror::Error;

use crate::Packet;
use crate::build::{BuildContext, BuildMode};
use crate::diagnostic::Diagnostic;
use crate::field::FieldValue;
use crate::layer::{FieldError, Layer, LayerSchema, ProtocolId};
use crate::layout::FieldLayout;
use crate::registry::{Discriminator, ProtocolRegistry};

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

pub struct LayerEncodeContext<'a> {
    pub packet: &'a Packet,
    pub index: usize,
    pub build_context: &'a BuildContext,
    pub mode: BuildMode,
    pub registry: &'a ProtocolRegistry,
    pub child: Option<&'a dyn Layer>,
    /// Maximum additional bytes this layer may contribute without exceeding
    /// the operation's configured packet-size limit. External codecs should
    /// check this before allocating output buffers.
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

pub struct LayerDecodeContext<'a> {
    pub registry: &'a ProtocolRegistry,
    pub layer_index: usize,
    pub absolute_offset: usize,
    pub verify_checksums: bool,
    /// Whether bytes outside an IP-declared length may be link-layer padding.
    pub allow_trailing_padding: bool,
    /// Network pseudo-header context established by an enclosing IP codec.
    pub network: Option<NetworkEnvelope>,
    /// Discriminator through which the parent binding selected this layer;
    /// `None` at the capture root. Codecs whose parent registers them under
    /// more than one discriminator — PPPoE's two stage EtherTypes — read it
    /// to interpret ambiguous headers the way the enclosing frame declared.
    pub discriminator: Option<Discriminator>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NetworkEnvelope {
    pub source: IpAddr,
    pub destination: IpAddr,
}

pub struct DecodedLayerValue {
    pub layer: Box<dyn Layer>,
    /// Number of leading input bytes consumed by this layer. The child
    /// payload, when present, begins at this offset.
    pub consumed: usize,
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
            payload_len: 0,
            next: Vec::new(),
            fields: Vec::new(),
            diagnostics: Vec::new(),
            stop: true,
            network: None,
        }
    }
}

/// Encoder, bounded decoder, and expression factory for one protocol.
pub trait LayerCodec: Send + Sync + fmt::Debug {
    fn protocol_id(&self) -> ProtocolId;

    /// Whether a decoded layer protocol is a valid result for this codec.
    /// Most codecs return their own protocol. A decode-only multiplexing root
    /// may explicitly admit the concrete protocols it selects.
    fn accepts_decoded_protocol(&self, protocol: &ProtocolId) -> bool {
        *protocol == self.protocol_id()
    }

    fn aliases(&self) -> &'static [&'static str] {
        &[]
    }

    /// Publishes the reflective schema without requiring a constructible
    /// layer. The default keeps existing codecs on their factory-based path.
    fn published_schema(&self) -> Option<&'static LayerSchema> {
        let fields = BTreeMap::new();
        self.make_layer(&fields).ok().map(|layer| layer.schema())
    }

    fn encode(
        &self,
        layer: &dyn Layer,
        payload: &[u8],
        context: &LayerEncodeContext<'_>,
    ) -> Result<EncodedLayer, CodecError>;

    fn decode(
        &self,
        input: &[u8],
        context: &LayerDecodeContext<'_>,
    ) -> Result<DecodedLayerValue, CodecError>;

    /// Constructs one layer from caller-supplied reflective fields.
    ///
    /// Implementations may fill omitted fields with defaults. The returned
    /// layer must satisfy [`Layer::validate_required_fields`]; the public
    /// expression/document paths and the builder enforce that invariant.
    fn make_layer(
        &self,
        fields: &BTreeMap<String, FieldValue>,
    ) -> Result<Box<dyn Layer>, CodecError>;
}
