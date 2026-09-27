// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

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

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Context {
    pub source: Option<IpAddr>,
    pub destination: Option<IpAddr>,
}

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
    #[error("invalid {protocol} layer: {message}")]
    Invalid { protocol: Id, message: String },
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
    /// External codecs should check this before allocating output buffers.
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
    pub parent: Option<Id>,
    pub registry: &'a Registry,
    pub allow_trailing_padding: bool,
    pub network: Option<NetworkEnvelope>,
    pub discriminator: Option<Discriminator>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NetworkEnvelope {
    pub source: IpAddr,
    pub destination: IpAddr,
}

pub struct DecodedLayer {
    pub layer: Box<dyn Layer>,
    pub consumed: usize,
    pub payload_len: usize,
    pub next: Vec<Discriminator>,
    pub fields: Vec<FieldLayout>,
    pub diagnostics: Vec<Diagnostic>,
    pub stop: bool,
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

pub trait LayerCodec: Send + Sync + fmt::Debug {
    fn protocol_id(&self) -> &'static Id;

    fn accepts_decoded_protocol(&self, protocol: &Id) -> bool {
        protocol == self.protocol_id()
    }

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

    fn decode(&self, input: Bytes, context: &LayerDecodeContext<'_>)
    -> Result<DecodedLayer, Error>;

    fn make_layer(&self, fields: &BTreeMap<String, FieldValue>) -> Result<Box<dyn Layer>, Error>;
}
