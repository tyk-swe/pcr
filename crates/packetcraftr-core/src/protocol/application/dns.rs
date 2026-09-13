// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Bounded, lossless DNS message dissection and resource-record decoding.

use std::collections::BTreeMap;

use bytes::Bytes;

use crate::{
    codec::{DecodedLayer, EncodedLayer, LayerCodec, LayerDecodeContext, LayerEncodeContext},
    field::{FieldValue, WireValue},
    layer::{Layer, reflective_layer},
};

use crate::protocol::common::{
    ensure_encode_budget, invalid, protocol, read_only, truncated, typed_layer,
};

use crate::protocol::BuiltinProtocol;

mod decode;
mod encode;
mod error;
pub mod name;
mod records;
mod reflection;

pub use decode::{decode_name, read_u16, read_u32};
pub use error::DecodeError;
pub use records::{Edns, EdnsOption, Name, Question, Record, RecordValue};

const NAME: &str = BuiltinProtocol::Dns.as_str();
pub(crate) const HEADER_LEN: usize = 12;

/// Per-message resource bounds. Absolute ceilings remain 65,535 message/TXT
/// bytes, 4,096 records/TXT strings, 128 name pointers, and 64 questions.
/// Larger supplied limits are tightened to these ceilings; zero permits none.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DecodeLimits {
    pub max_message_bytes: usize,
    pub max_records: usize,
    pub max_name_pointers: usize,
    pub max_txt_strings: usize,
    pub max_txt_bytes: usize,
}
impl Default for DecodeLimits {
    fn default() -> Self {
        Self {
            max_message_bytes: 65_535,
            max_records: 512,
            max_name_pointers: 32,
            max_txt_strings: 256,
            max_txt_bytes: 16_384,
        }
    }
}

/// The bounded, exact DNS-over-UDP layer.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Dns {
    pub id: u16,
    pub response: bool,
    pub opcode: u8,
    pub authoritative_answer: bool,
    pub truncated: bool,
    pub recursion_desired: bool,
    pub recursion_available: bool,
    pub authenticated_data: bool,
    pub checking_disabled: bool,
    pub rcode: u8,
    pub question_count: WireValue<u16>,
    pub answer_count: WireValue<u16>,
    pub authority_count: WireValue<u16>,
    pub additional_count: WireValue<u16>,
    pub questions: Vec<Question>,
    /// Reserved header bit retained for protocol fixtures.
    pub reserved: bool,
    pub answers: Vec<Record>,
    pub authorities: Vec<Record>,
    pub additionals: Vec<Record>,
    wire: Bytes,
}

impl Dns {
    /// Parses a complete DNS message under the default bounded decoder limits.
    pub fn from_wire(wire: impl Into<Bytes>) -> Result<Self, crate::codec::Error> {
        let wire = wire.into();
        let available = wire.len();
        Self::from_wire_with_limits(wire, DecodeLimits::default()).map_err(|error| {
            error.truncation_needed().map_or_else(
                || invalid(NAME, error.to_string()),
                |needed| truncated(NAME, needed, available),
            )
        })
    }

    /// Decodes every declared section while retaining the complete original
    /// wire. Malformed or truncated data returns a typed failure, never an
    /// invented record. OPT records remain in their original section.
    pub fn from_wire_with_limits(
        wire: impl Into<Bytes>,
        limits: DecodeLimits,
    ) -> Result<Self, DecodeError> {
        decode::decode(wire.into(), limits)
    }

    /// Returns the complete original DNS payload, including opaque records.
    pub fn wire(&self) -> &Bytes {
        &self.wire
    }

    /// Begins an explicit edit, deriving section counts from the new record sets.
    pub fn edit(&mut self, edit: impl FnOnce(&mut Self)) {
        self.wire = Bytes::new();
        self.question_count = WireValue::Auto;
        self.answer_count = WireValue::Auto;
        self.authority_count = WireValue::Auto;
        self.additional_count = WireValue::Auto;
        edit(self);
    }

    /// Encodes a complete message with strict validation and the DNS wire ceiling.
    pub fn to_wire(&self) -> Result<Bytes, crate::codec::Error> {
        encode::message(self, crate::codec::Mode::Strict, 65_535)
            .map(|encoded| Bytes::from(encoded.0))
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

    fn assign(&mut self, name: &str, value: FieldValue) -> Result<(), crate::layer::FieldError> {
        let mut candidate = self.clone();
        if !candidate.wire.is_empty() {
            candidate.edit(|_| {});
        }
        reflection::assign(&mut candidate, name, value)?;
        *self = candidate;
        Ok(())
    }
}

reflective_layer! {
    fn dns_schema() => { protocol: protocol(NAME), name: "DNS" }
    impl Dns {
        "id" => { kind: Unsigned, derived: false, required: false, description: "Transaction identifier", get |layer| Some(crate::layer::reflect_get(&layer.id)), set |layer, value, name| layer.assign(name, value), layout: (0, 2) },
        "response" => { kind: Bool, derived: false, required: false, description: "Query/response flag", get |layer| Some(crate::layer::reflect_get(&layer.response)), set |layer, value, name| layer.assign(name, value), layout: (2, 4) },
        "opcode" => { kind: Unsigned, derived: false, required: false, description: "Operation code", get |layer| Some(crate::layer::reflect_get(&layer.opcode)), set |layer, value, name| layer.assign(name, value), layout: (2, 4) },
        "authoritative_answer" => { kind: Bool, derived: false, required: false, description: "Authoritative-answer flag", get |layer| Some(crate::layer::reflect_get(&layer.authoritative_answer)), set |layer, value, name| layer.assign(name, value), layout: (2, 4) },
        "truncated" => { kind: Bool, derived: false, required: false, description: "Truncated response flag", get |layer| Some(crate::layer::reflect_get(&layer.truncated)), set |layer, value, name| layer.assign(name, value), layout: (2, 4) },
        "recursion_desired" => { kind: Bool, derived: false, required: false, description: "Recursion-desired flag", get |layer| Some(crate::layer::reflect_get(&layer.recursion_desired)), set |layer, value, name| layer.assign(name, value), layout: (2, 4) },
        "recursion_available" => { kind: Bool, derived: false, required: false, description: "Recursion-available flag", get |layer| Some(crate::layer::reflect_get(&layer.recursion_available)), set |layer, value, name| layer.assign(name, value), layout: (2, 4) },
        "reserved" => { kind: Bool, derived: false, required: false, description: "Reserved header bit", get |layer| Some(crate::layer::reflect_get(&layer.reserved)), set |layer, value, name| layer.assign(name, value), layout: (2, 4) },
        "authenticated_data" => { kind: Bool, derived: false, required: false, description: "Authenticated-data flag", get |layer| Some(crate::layer::reflect_get(&layer.authenticated_data)), set |layer, value, name| layer.assign(name, value), layout: (2, 4) },
        "checking_disabled" => { kind: Bool, derived: false, required: false, description: "Checking-disabled flag", get |layer| Some(crate::layer::reflect_get(&layer.checking_disabled)), set |layer, value, name| layer.assign(name, value), layout: (2, 4) },
        "rcode" => { kind: Unsigned, derived: false, required: false, description: "Response code", get |layer| Some(crate::layer::reflect_get(&layer.rcode)), set |layer, value, name| layer.assign(name, value), layout: (2, 4) },
        "question_count" => { kind: Unsigned, derived: true, required: false, description: "Question count", get |layer| Some(crate::layer::reflect_get(&layer.question_count)), set |layer, value, name| layer.assign(name, value), layout: (4, 6) },
        "answer_count" => { kind: Unsigned, derived: true, required: false, description: "Answer count", get |layer| Some(crate::layer::reflect_get(&layer.answer_count)), set |layer, value, name| layer.assign(name, value), layout: (6, 8) },
        "authority_count" => { kind: Unsigned, derived: true, required: false, description: "Authority-record count", get |layer| Some(crate::layer::reflect_get(&layer.authority_count)), set |layer, value, name| layer.assign(name, value), layout: (8, 10) },
        "additional_count" => { kind: Unsigned, derived: true, required: false, description: "Additional-record count", get |layer| Some(crate::layer::reflect_get(&layer.additional_count)), set |layer, value, name| layer.assign(name, value), layout: (10, 12) },
        "questions" => { kind: List, derived: false, required: false, description: "Ordered DNS questions", children: reflection::QUESTION_FIELDS, get |layer| Some(reflection::questions(&layer.questions)), set |layer, value, name| layer.assign(name, value) },
        "answers" => { kind: List, derived: false, required: false, description: "Answer records", children: reflection::RECORD_FIELDS, get |layer| Some(reflection::records(&layer.answers)), set |layer, value, name| layer.assign(name, value) },
        "authorities" => { kind: List, derived: false, required: false, description: "Authority records", children: reflection::RECORD_FIELDS, get |layer| Some(reflection::records(&layer.authorities)), set |layer, value, name| layer.assign(name, value) },
        "additionals" => { kind: List, derived: false, required: false, description: "Additional records", children: reflection::RECORD_FIELDS, get |layer| Some(reflection::records(&layer.additionals)), set |layer, value, name| layer.assign(name, value) },
        "qname" => { kind: List, derived: false, required: false, description: "Question qname values", get |layer| Some(FieldValue::List(layer.questions.iter().map(|q| (q.name.to_string().replace("\\032", " ")).into()).collect())), set |_layer, _value, name| read_only(dns_schema(), name) },
        "qtype" => { kind: List, derived: false, required: false, description: "Question qtype values", get |layer| Some(FieldValue::List(layer.questions.iter().map(|q| (q.query_type).into()).collect())), set |_layer, _value, name| read_only(dns_schema(), name) },
        "qclass" => { kind: List, derived: false, required: false, description: "Question qclass values", get |layer| Some(FieldValue::List(layer.questions.iter().map(|q| (q.class).into()).collect())), set |_layer, _value, name| read_only(dns_schema(), name) },
        "wire" => { kind: Bytes, derived: false, required: false, description: "Retained original message; explicit field edits invalidate it", get |layer| (!layer.wire.is_empty()).then(|| layer.wire.clone().into()), set |_layer, _value, name| read_only(dns_schema(), name) }
    }
    layout pub(crate) fn dns_layout();
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
        input: &[u8],
        context: &LayerDecodeContext<'_>,
    ) -> Result<DecodedLayer, crate::codec::Error> {
        if context.parent == Some(protocol("tcp")) {
            let parsed = input
                .get(..2)
                .map(|bytes| usize::from(u16::from_be_bytes([bytes[0], bytes[1]])))
                .filter(|length| *length >= HEADER_LEN)
                .and_then(|length| input.get(2..length + 2).map(|body| (length, body)))
                .and_then(|(length, body)| {
                    Dns::from_wire(Bytes::copy_from_slice(body))
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
                layer: Box::new(crate::layer::Raw::new(Bytes::copy_from_slice(input))),
                consumed: input.len(),
                payload_len: 0,
                next: Vec::new(),
                fields: crate::layer::raw_layout(input.len()),
                diagnostics: Vec::new(),
                stop: true,
                network: None,
            });
        }
        let maximum = DecodeLimits::default().max_message_bytes;
        if input.len() > maximum {
            return Err(invalid(
                NAME,
                DecodeError::MessageTooLarge {
                    actual: input.len(),
                    maximum,
                }
                .to_string(),
            ));
        }
        let layer = Dns::from_wire(Bytes::copy_from_slice(input))?;
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
            Dns::from_wire(wire.clone())?
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
            layer.set_field_path(name, value.clone())?;
        }
        Ok(Box::new(layer))
    }
}
