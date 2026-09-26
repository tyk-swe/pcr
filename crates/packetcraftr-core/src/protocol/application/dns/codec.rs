// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! The DNS wire codec: bounded decoding, strict encoding, and the layer codec
//! that frames DNS over UDP and TCP.

use std::collections::BTreeMap;

use bytes::Bytes;

use super::reflection::{dns_layout, dns_schema};
use super::{DecodeLimits, Dns, Error};
use crate::{
    codec::{DecodedLayer, EncodedLayer, LayerCodec, LayerDecodeContext, LayerEncodeContext},
    field::FieldValue,
    layer::Layer,
    protocol::{
        BuiltinProtocol,
        common::{ensure_encode_budget, invalid, protocol, truncated, typed_layer},
    },
};

mod decode;
mod encode;
pub mod name;

pub use decode::{decode_name, read_u16};

pub(super) const NAME: &str = BuiltinProtocol::Dns.as_str();
pub(super) const HEADER_LEN: usize = 12;

impl TryFrom<Bytes> for Dns {
    type Error = Error;

    /// Parses a complete DNS message under the default bounded decoder limits.
    fn try_from(wire: Bytes) -> Result<Self, Self::Error> {
        Self::from_wire_with_limits(wire, DecodeLimits::default())
    }
}

impl TryFrom<Vec<u8>> for Dns {
    type Error = Error;

    fn try_from(wire: Vec<u8>) -> Result<Self, Self::Error> {
        Self::try_from(Bytes::from(wire))
    }
}

impl TryFrom<&[u8]> for Dns {
    type Error = Error;

    fn try_from(wire: &[u8]) -> Result<Self, Self::Error> {
        let maximum = DecodeLimits::default().max_message_bytes;
        if wire.len() > maximum {
            return Err(Error::MessageTooLarge {
                actual: wire.len(),
                maximum,
            });
        }
        Self::try_from(Bytes::copy_from_slice(wire))
    }
}

impl Dns {
    /// Decodes every declared section while retaining the complete original
    /// wire. Malformed or truncated data returns a typed failure, never an
    /// invented record. OPT records remain in their original section.
    pub fn from_wire_with_limits(
        wire: impl Into<Bytes>,
        limits: DecodeLimits,
    ) -> Result<Self, Error> {
        decode::decode(wire.into(), limits)
    }

    /// Encodes a complete message with strict validation and the DNS wire ceiling.
    pub fn to_wire(&self) -> Result<Bytes, Error> {
        encode::message(self, crate::codec::Mode::Strict, 65_535)
            .map(|encoded| Bytes::from(encoded.0))
            .map_err(Error::Encode)
    }

    fn retained_wire_matches(&self) -> bool {
        if self.wire.is_empty() {
            return false;
        }
        Self::from_wire_with_limits(
            self.wire.clone(),
            DecodeLimits {
                max_records: 4096,
                max_name_pointers: 128,
                max_txt_strings: 4096,
                max_txt_bytes: 65_535,
                ..DecodeLimits::default()
            },
        )
        .is_ok_and(|parsed| {
            dns_schema()
                .fields
                .iter()
                .all(|field| self.field(field.name) == parsed.field(field.name))
        })
    }
}

/// Reports a wire failure through the layer codec contract: truncation keeps
/// the byte count it needs, anything else is an invalid DNS layer.
fn layer_error(error: Error, available: usize) -> crate::codec::Error {
    match error {
        Error::Encode(error) => error,
        error => error.truncation_needed().map_or_else(
            || invalid(NAME, error.to_string()),
            |needed| truncated(NAME, needed, available),
        ),
    }
}

fn layer_from_wire(wire: Bytes) -> Result<Dns, crate::codec::Error> {
    let available = wire.len();
    Dns::try_from(wire).map_err(|error| layer_error(error, available))
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct DnsCodec;

impl LayerCodec for DnsCodec {
    fn accepts_decoded_protocol(&self, protocol: &crate::layer::Id) -> bool {
        matches!(protocol.as_str(), "dns" | "raw")
    }

    fn protocol_id(&self) -> &'static crate::layer::Id {
        &dns_schema().protocol
    }

    fn published_schema(&self) -> Option<&'static crate::layer::Schema> {
        Some(dns_schema())
    }

    fn encode(
        &self,
        layer: &dyn Layer,
        payload: &[u8],
        context: &LayerEncodeContext<'_>,
    ) -> Result<EncodedLayer, crate::codec::Error> {
        let layer = typed_layer::<Dns>(NAME, layer)?;
        let tcp = context
            .index
            .checked_sub(1)
            .and_then(|index| context.packet.layer(index))
            .is_some_and(|parent| BuiltinProtocol::Tcp.identifies(parent));
        if (!tcp && (context.child.is_some() || !payload.is_empty()))
            || (tcp
                && context.child.is_some_and(|child| {
                    !BuiltinProtocol::Raw.identifies(child)
                        && !BuiltinProtocol::Padding.identifies(child)
                }))
        {
            return Err(invalid(NAME, "DNS permits only a raw TCP framing tail"));
        }
        let prefix = usize::from(tcp) * 2;
        let available = context
            .remaining_packet_bytes
            .checked_sub(prefix)
            .ok_or_else(|| invalid(NAME, "DNS framing exceeds packet budget"))?;
        let (mut wire, mut materialized, diagnostics) =
            encode::message(layer, context.mode, available)?;
        materialized.wire = Bytes::copy_from_slice(&wire);
        if tcp {
            let length = (wire.len() as u16).to_be_bytes();
            wire.splice(..0, length);
        }
        ensure_encode_budget(NAME, wire.len(), context)?;
        let mut fields = dns_layout();
        for field in &mut fields {
            field.range.start += prefix;
            field.range.end += prefix;
        }
        Ok(EncodedLayer::header(wire, Box::new(materialized))
            .with_fields(fields)
            .with_diagnostics(diagnostics))
    }

    fn decode(
        &self,
        input: Bytes,
        context: &LayerDecodeContext<'_>,
    ) -> Result<DecodedLayer, crate::codec::Error> {
        if context.parent == Some(protocol("tcp")) {
            let parsed = input
                .get(..2)
                .map(|bytes| usize::from(u16::from_be_bytes([bytes[0], bytes[1]])))
                .filter(|length| *length >= HEADER_LEN)
                .and_then(|length| input.get(2..length + 2).map(|body| (length, body)))
                .and_then(|(length, body)| {
                    Dns::try_from(input.slice_ref(body))
                        .ok()
                        .map(|layer| (length, layer))
                });
            if let Some((length, layer)) = parsed {
                let consumed = length + 2;
                let remaining = input.len() - consumed;
                let mut fields = dns_layout();
                for field in &mut fields {
                    field.range.start += 2;
                    field.range.end += 2;
                }
                return Ok(DecodedLayer {
                    layer: Box::new(layer),
                    consumed,
                    payload_len: remaining,
                    next: if remaining > 0 {
                        vec![crate::registry::Discriminator(0)]
                    } else {
                        Vec::new()
                    },
                    fields,
                    diagnostics: Vec::new(),
                    stop: remaining == 0,
                    network: None,
                });
            }
            return Ok(DecodedLayer {
                layer: Box::new(crate::layer::Raw::new(input.clone())),
                consumed: input.len(),
                payload_len: 0,
                next: Vec::new(),
                fields: crate::layer::raw_layout(input.len()),
                diagnostics: Vec::new(),
                stop: true,
                network: None,
            });
        }
        let layer = layer_from_wire(input.clone())?;
        Ok(DecodedLayer {
            layer: Box::new(layer),
            consumed: input.len(),
            payload_len: 0,
            next: Vec::new(),
            fields: dns_layout(),
            diagnostics: Vec::new(),
            stop: true,
            network: None,
        })
    }

    fn make_layer(
        &self,
        fields: &BTreeMap<String, FieldValue>,
    ) -> Result<Box<dyn Layer>, crate::codec::Error> {
        let mut layer = if let Some(FieldValue::Bytes(wire)) = fields.get("wire") {
            layer_from_wire(wire.clone())?
        } else {
            Dns::default()
        };
        for (name, value) in fields {
            if name == "wire" {
                if !matches!(value, FieldValue::Bytes(_)) {
                    return Err(invalid(NAME, "wire must be bytes"));
                }
                continue;
            }
            if layer.field(name).as_ref() == Some(value) {
                continue;
            }
            crate::protocol::common::set_document_field(&mut layer, name, value.clone())?;
        }
        Ok(Box::new(layer))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn question(extra: &[u8]) -> Bytes {
        let mut wire = vec![0; 12];
        wire[4..6].copy_from_slice(&1_u16.to_be_bytes());
        wire.extend_from_slice(extra);
        wire.into()
    }

    #[test]
    fn layer_errors_keep_the_extent_a_truncated_message_needs() {
        let mut rdata = vec![0; 12];
        rdata[6..8].copy_from_slice(&1_u16.to_be_bytes());
        rdata.extend_from_slice(&[0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 4, 192, 0]);
        for (wire, expected) in [
            (Bytes::from(vec![0; 11]), 12),
            (question(&[3, b'w', b'w']), 16),
            (question(&[0, 0]), 15),
            (rdata.into(), 27),
        ] {
            let available = wire.len();
            assert!(
                matches!(
                    layer_from_wire(wire),
                    Err(crate::codec::Error::Truncated { needed, available: actual, .. })
                        if needed == expected && actual == available
                ),
                "needs {expected}"
            );
        }
    }

    #[test]
    fn layer_errors_report_other_failures_as_invalid_dns() {
        let mut too_many = vec![0; 12];
        too_many[4..6].copy_from_slice(&65_u16.to_be_bytes());
        let error = layer_from_wire(too_many.into()).unwrap_err();
        assert_eq!(
            error,
            invalid(NAME, "DNS question count 65 exceeds limit 64")
        );
    }
}
