// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Extension contract for packet codecs.

use std::collections::BTreeMap;
use std::fmt;
use std::net::IpAddr;

use bytes::Bytes;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::packet::Packet;

use crate::diagnostic::Diagnostic;
use crate::error::{Classification, Classified, Kind, Source};
use crate::field::{self, FieldValue};
use crate::layer::{Id, Layer, Schema};
use crate::layout::FieldLayout;
use crate::registry::{Discriminator, Registry};

/// How strictly a codec treats a construct the wire format allows but the
/// protocol does not: `Strict` refuses it, `Permissive` encodes it and raises
/// a diagnostic.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    #[default]
    Strict,
    Permissive,
}

/// Addresses an enclosing operation supplies so codecs can derive fields the
/// packet itself does not carry, such as a transport pseudo-header.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Context {
    pub source: Option<IpAddr>,
    pub destination: Option<IpAddr>,
}

/// Why a codec refused to decode, encode, or construct a layer.
///
/// Not `Eq`: a [`Error::Rejected`] source compares by its rendered chain.
#[derive(Clone, Debug, Error, PartialEq)]
#[non_exhaustive]
pub enum Error {
    #[error("codec expected layer {expected}, got {actual}")]
    WrongLayer { expected: Id, actual: Id },
    #[error("truncated {protocol} layer: need at least {needed} bytes, got {available}")]
    Truncated {
        protocol: Id,
        needed: usize,
        available: usize,
    },
    /// The codec's own rule refused the layer; `message` states the rule.
    #[error("invalid {protocol} layer: {message}")]
    Invalid { protocol: Id, message: String },
    /// The protocol's typed model refused the layer; `source` says why.
    #[error("invalid {protocol} layer")]
    Rejected {
        protocol: Id,
        #[source]
        source: Source,
    },
    #[error("unsupported {protocol} construct: {message}")]
    Unsupported { protocol: Id, message: String },
    #[error("packet length arithmetic overflow while processing {protocol}")]
    LengthOverflow { protocol: Id },
    #[error(transparent)]
    Field(#[from] field::Error),
}

impl Error {
    /// Reports a protocol's typed failure as an invalid `protocol` layer,
    /// retaining it as the source.
    pub fn rejected(protocol: Id, source: impl std::error::Error + Send + Sync + 'static) -> Self {
        Self::Rejected {
            protocol,
            source: Source::new(source),
        }
    }
}

impl Classified for Error {
    fn classification(&self) -> Classification {
        match self {
            Self::Field(source) => source.classification(),
            Self::WrongLayer { .. } => Classification::new(
                "internal.codec_contract",
                Kind::Internal,
                Some("report the codec that was handed a layer of another protocol"),
            ),
            Self::LengthOverflow { .. } => Classification::new(
                "packet.length_overflow",
                Kind::Packet,
                Some("shrink the packet so its byte offsets stay representable"),
            ),
            Self::Truncated { .. }
            | Self::Invalid { .. }
            | Self::Rejected { .. }
            | Self::Unsupported { .. } => Classification::new(
                "packet.codec",
                Kind::Packet,
                Some("correct the layer bytes or field values the codec refused"),
            ),
        }
    }
}

pub struct LayerEncodeContext<'a> {
    pub packet: &'a Packet,
    pub index: usize,
    pub build_context: &'a Context,
    pub mode: Mode,
    pub registry: &'a Registry,
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
    /// A layer that contributes a header and no trailer, which is every
    /// built-in codec. A codec that emits trailing bytes assigns
    /// [`Self::suffix`] afterwards.
    pub fn header(prefix: Vec<u8>, materialized: Box<dyn Layer>) -> Self {
        Self {
            prefix,
            suffix: Vec::new(),
            materialized,
            fields: Vec::new(),
            diagnostics: Vec::new(),
        }
    }

    #[must_use]
    pub fn with_fields(mut self, fields: Vec<FieldLayout>) -> Self {
        self.fields = fields;
        self
    }

    #[must_use]
    pub fn with_diagnostics(mut self, diagnostics: Vec<Diagnostic>) -> Self {
        self.diagnostics = diagnostics;
        self
    }
}

pub struct LayerDecodeContext<'a> {
    /// The decoded parent layer, absent at the capture root.
    pub parent: Option<Id>,
    pub registry: &'a Registry,
    /// Whether bytes outside an IP-declared length may be link-layer padding.
    pub allow_trailing_padding: bool,
    /// Network pseudo-header context established by an enclosing IP codec.
    pub network: Option<NetworkEnvelope>,
    /// Parent-binding discriminator; `None` at the root. Distinguishes
    /// ambiguous headers registered under multiple discriminators, such as
    /// PPPoE stages.
    pub discriminator: Option<Discriminator>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NetworkEnvelope {
    pub source: IpAddr,
    pub destination: IpAddr,
}

pub struct DecodedLayer {
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

impl DecodedLayer {
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
    /// The protocol this codec registers under, borrowed from the protocol's
    /// own reflective schema so no call allocates.
    fn protocol_id(&self) -> &'static Id;

    /// Whether a decoded layer protocol is a valid result for this codec.
    /// Most codecs return their own protocol. A decode-only multiplexing root
    /// may explicitly admit the concrete protocols it selects.
    fn accepts_decoded_protocol(&self, protocol: &Id) -> bool {
        protocol == self.protocol_id()
    }

    /// Publishes the reflective schema without requiring a constructible
    /// layer. The default derives the schema from a default-constructed layer.
    fn published_schema(&self) -> Option<&'static Schema> {
        let fields = BTreeMap::new();
        self.make_layer(&fields).ok().map(|layer| layer.schema())
    }

    fn encode(
        &self,
        layer: &dyn Layer,
        payload: &[u8],
        context: &LayerEncodeContext<'_>,
    ) -> Result<EncodedLayer, Error>;

    /// Decodes one layer from `input`, a refcounted view the codec may retain
    /// (whole or via `Bytes::slice`) without copying. Callers that only hold a
    /// borrowed slice copy it once into `Bytes` before calling.
    fn decode(&self, input: Bytes, context: &LayerDecodeContext<'_>)
    -> Result<DecodedLayer, Error>;

    /// Constructs a layer from reflective fields, optionally defaulting
    /// omissions. Expression/document parsing and the builder enforce
    /// [`Layer::validate_required_fields`] on the result.
    fn make_layer(&self, fields: &BTreeMap<String, FieldValue>) -> Result<Box<dyn Layer>, Error>;
}
