// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::BTreeMap;
use std::fmt;
use std::net::IpAddr;

use bytes::Bytes;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::diagnostic::Diagnostic;
use crate::error::{Classification, Classified, Kind, Source};
use crate::field;
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
pub struct Addresses {
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

    pub(crate) fn invalid(protocol: Id, message: impl Into<String>) -> Self {
        Self::Invalid {
            protocol,
            message: message.into(),
        }
    }

    pub(crate) fn unsupported(protocol: Id, message: impl Into<String>) -> Self {
        Self::Unsupported {
            protocol,
            message: message.into(),
        }
    }

    pub(crate) fn wrong_layer(expected: Id, actual: &dyn Layer) -> Self {
        Self::WrongLayer {
            expected,
            actual: *actual.protocol_id(),
        }
    }
}

impl Classified for Error {
    fn classification(&self) -> Classification {
        match self {
            Self::Field(source) => source.classification(),
            Self::WrongLayer { .. } => Classification::new(
                crate::error::Code::InternalCodecContract,
                Kind::Internal,
                Some("report the codec that was handed a layer of another protocol"),
            ),
            Self::LengthOverflow { .. } => Classification::new(
                crate::error::Code::PacketLengthOverflow,
                Kind::Packet,
                Some("shrink the packet so its byte offsets stay representable"),
            ),
            Self::Truncated { .. }
            | Self::Invalid { .. }
            | Self::Rejected { .. }
            | Self::Unsupported { .. } => Classification::new(
                crate::error::Code::PacketCodec,
                Kind::Packet,
                Some("correct the layer bytes or field values the codec refused"),
            ),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChildInfo {
    pub protocol: Id,
    pub binding: String,
    pub builtin: Option<Id>,
    pub binds_as: Option<Id>,
    pub opaque: bool,
    pub discriminator: Option<Discriminator>,
}

impl ChildInfo {
    pub fn protocol_id(&self) -> &Id {
        &self.protocol
    }

    pub fn binding_protocol(&self) -> &str {
        &self.binding
    }

    pub fn is_opaque(&self) -> bool {
        self.opaque
    }

    pub fn is_builtin(&self, protocol: Id) -> bool {
        self.builtin == Some(protocol)
    }

    pub fn binds_as(&self, protocol: Id) -> bool {
        self.binds_as == Some(protocol)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParentInfo {
    pub protocol: Id,
    pub builtin: Option<Id>,
    pub discriminator_value: Option<field::Value>,
    pub protocol_type_value: Option<field::Value>,
    pub gre_sequence_present: Option<bool>,
}

impl ParentInfo {
    pub fn is_builtin(&self, protocol: Id) -> bool {
        self.builtin == Some(protocol)
    }
}

pub struct EncodeContext<'a> {
    pub addresses: &'a Addresses,
    pub mode: Mode,
    pub child: Option<&'a ChildInfo>,
    pub parent: Option<&'a ParentInfo>,
    pub network: Result<NetworkEnvelope, Error>,
    pub outer_network: bool,
    pub srh_active_segment: Option<std::net::Ipv6Addr>,
    pub srh_reduced: bool,
    pub under_ipv6: Option<bool>,
    pub trailing_padding: Option<usize>,
    pub child_bindings: &'a [(Discriminator, Id)],
    /// External codecs should check this before allocating output buffers.
    pub remaining_packet_bytes: usize,
}

impl EncodeContext<'_> {
    pub fn child_for(&self, discriminator: Discriminator) -> Option<Id> {
        self.child_bindings
            .iter()
            .find(|(candidate, _)| *candidate == discriminator)
            .map(|(_, child)| *child)
    }

    pub fn network_envelope(&self) -> Result<NetworkEnvelope, Error> {
        self.network.clone()
    }

    pub(crate) fn ensure_room(&self, protocol: Id, contribution: usize) -> Result<(), Error> {
        if contribution > self.remaining_packet_bytes {
            return Err(Error::invalid(
                protocol,
                format!(
                    "layer contributes {contribution} bytes but only {} remain in the packet-size budget",
                    self.remaining_packet_bytes
                ),
            ));
        }
        Ok(())
    }
}

pub struct Encoded {
    pub prefix: Vec<u8>,
    pub suffix: Vec<u8>,
    pub materialized: Box<dyn Layer>,
    pub fields: Vec<FieldLayout>,
    pub diagnostics: Vec<Diagnostic>,
}

impl Encoded {
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

pub struct DecodeContext<'a> {
    pub parent: Option<Id>,
    pub registry: &'a Registry,
    pub network: Option<NetworkEnvelope>,
    /// The TTL or hop limit of the IP header that produced `network`.
    pub hop_limit: Option<u8>,
    pub discriminator: Option<Discriminator>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NetworkEnvelope {
    pub source: IpAddr,
    pub destination: IpAddr,
}

pub struct Decoded {
    pub layer: Box<dyn Layer>,
    pub consumed: usize,
    pub payload_len: usize,
    pub next: Vec<Discriminator>,
    pub fields: Vec<FieldLayout>,
    pub diagnostics: Vec<Diagnostic>,
    pub stop: bool,
    pub network: Option<NetworkEnvelope>,
}

impl Decoded {
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

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Framing {
    #[default]
    Datagram,
    Control,
    Lacp,
    Mqtt,
    Amqp,
    Bgp,
    Ber,
    Resp,
    Sip,
    Rtsp,
    Memcached,
    Ipfix,
    Radius,
    Stun,
    ModbusTcp,
    Dnp3,
    EthernetIp,
    Iec104,
    OpcuaTcp,
}

pub struct SeededLayer {
    pub layer: Box<dyn Layer>,
    pub consumed: Option<usize>,
}

pub trait Codec: Send + Sync + fmt::Debug {
    fn protocol_id(&self) -> &'static Id;

    fn schema(&self) -> Option<&'static Schema>;

    fn new_layer(&self) -> Result<Box<dyn Layer>, Error>;

    fn accepts_decoded_protocol(&self, protocol: &Id) -> bool {
        protocol == self.protocol_id()
    }

    fn framing(&self) -> Framing {
        Framing::Datagram
    }

    fn prepare_fields(
        &self,
        fields: BTreeMap<String, field::Value>,
    ) -> Result<BTreeMap<String, field::Value>, Error> {
        Ok(fields)
    }

    fn seed_layer(&self, _fields: &[(usize, &field::Value)]) -> Result<Option<SeededLayer>, Error> {
        Ok(None)
    }

    fn apply_constructed_field(
        &self,
        _layer: &mut dyn Layer,
        _index: usize,
        _value: field::Value,
    ) -> Option<Result<(), Error>> {
        None
    }

    fn finish_constructed(
        &self,
        _layer: &mut dyn Layer,
        _fields: &[(usize, &field::Value)],
    ) -> Result<(), Error> {
        Ok(())
    }

    fn construct(&self, fields: &BTreeMap<String, field::Value>) -> Result<Box<dyn Layer>, Error> {
        let Some(schema) = self.schema() else {
            return self.new_layer();
        };
        let fields = self.prepare_fields(fields.clone())?;
        reject_aliased_duplicates(schema, &fields)?;
        let mut resolved = Vec::with_capacity(fields.len());
        for (name, value) in &fields {
            let unknown = || field::Error::UnknownField {
                protocol: schema.protocol,
                field: name.clone(),
            };
            let path: field::Path = name.parse().map_err(|_| unknown())?;
            let root = schema.field_index(path.root()).ok_or_else(unknown)?;
            resolved.push(ResolvedField { root, path, value });
        }
        let root_fields: Vec<(usize, &field::Value)> = resolved
            .iter()
            .filter(|field| !field.path.is_nested())
            .map(|field| (field.root, field.value))
            .collect();
        let seeded = self.seed_layer(&root_fields)?;
        let (mut layer, seeded, consumed) = match seeded {
            Some(seeded) => (seeded.layer, true, seeded.consumed),
            None => (self.new_layer()?, false, None),
        };
        for field in &resolved {
            if field.path.is_nested() {
                layer.set_field_path(&field.path, field.value.clone())?;
                continue;
            }
            if consumed == Some(field.root) {
                continue;
            }
            if seeded && layer.field_by_index(field.root).as_ref() == Some(field.value) {
                continue;
            }
            if let Some(result) =
                self.apply_constructed_field(layer.as_mut(), field.root, field.value.clone())
            {
                result?;
            } else {
                layer.set_field_by_index(field.root, field.value.clone())?;
            }
        }
        self.finish_constructed(layer.as_mut(), &root_fields)?;
        Ok(layer)
    }

    fn encode(
        &self,
        layer: &dyn Layer,
        payload: &[u8],
        context: &EncodeContext<'_>,
    ) -> Result<Encoded, Error>;

    fn decode(&self, input: Bytes, context: &DecodeContext<'_>) -> Result<Decoded, Error>;
}

struct ResolvedField<'a> {
    root: usize,
    path: field::Path,
    value: &'a field::Value,
}

fn reject_aliased_duplicates(
    schema: &'static Schema,
    fields: &BTreeMap<String, field::Value>,
) -> Result<(), Error> {
    for declared in schema.fields {
        let mut supplied = std::iter::once(declared.name)
            .chain(declared.aliases.iter().copied())
            .filter(|spelling| fields.contains_key(*spelling));
        let (Some(first), Some(second)) = (supplied.next(), supplied.next()) else {
            continue;
        };
        return Err(Error::invalid(
            schema.protocol,
            format!("both {second} and {first} were supplied"),
        ));
    }
    Ok(())
}
