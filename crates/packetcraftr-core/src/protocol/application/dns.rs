// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Bounded, lossless DNS message dissection and resource-record decoding.

use std::collections::BTreeMap;

use bytes::Bytes;

use crate::{
    codec::{DecodedLayer, EncodedLayer, LayerCodec, LayerDecodeContext, LayerEncodeContext},
    field::FieldValue,
    layer::{Layer, reflective_layer},
};

use crate::protocol::common::{
    ensure_encode_budget, invalid, protocol, read_only, text_list, truncated, typed_layer,
    unsigned_list,
};

use crate::protocol::BuiltinProtocol;

mod decode;
mod error;
pub mod name;
mod records;
mod reflection;

pub use decode::{decode_name, read_u16, read_u32};
pub use error::DecodeError;
pub use records::{Edns, EdnsOption, Name, Record, RecordValue};

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
#[derive(Clone, Debug, PartialEq, Eq)]
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
    pub question_count: u16,
    pub answer_count: u16,
    pub authority_count: u16,
    pub additional_count: u16,
    pub qnames: Vec<String>,
    pub qtypes: Vec<u16>,
    pub qclasses: Vec<u16>,
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

    fn validate_wire_consistency(&self) -> Result<(), crate::codec::Error> {
        let parsed = Self::from_wire_with_limits(
            self.wire.clone(),
            DecodeLimits {
                max_records: 4096,
                max_name_pointers: 128,
                max_txt_strings: 4096,
                max_txt_bytes: 65_535,
                ..DecodeLimits::default()
            },
        )
        .map_err(|error| invalid(NAME, error.to_string()))?;
        // Name equality intentionally folds ASCII case for DNS semantics.
        // Reflection preserves that case, so compare the exact presented fields
        // before allowing the retained bytes to represent this layer.
        if dns_schema()
            .fields
            .iter()
            .all(|field| self.field(field.name) == parsed.field(field.name))
        {
            Ok(())
        } else {
            Err(invalid(
                NAME,
                "DNS fields were changed after dissection and no longer match the retained wire payload",
            ))
        }
    }
}

reflective_layer! {
    fn dns_schema() => { protocol: protocol(NAME), name: "DNS" }
    impl Dns {
        "id" => { kind: Unsigned, derived: false, required: false, description: "Transaction identifier", get |layer| Some(FieldValue::from(layer.id)), set |_layer, _value, name| read_only(dns_schema(), name), layout: (0, 2) },
        "response" => { kind: Bool, derived: false, required: false, description: "Query/response flag", get |layer| Some(FieldValue::from(layer.response)), set |_layer, _value, name| read_only(dns_schema(), name), layout: (2, 4) },
        "opcode" => { kind: Unsigned, derived: false, required: false, description: "Operation code", get |layer| Some(FieldValue::from(layer.opcode)), set |_layer, _value, name| read_only(dns_schema(), name), layout: (2, 4) },
        "authoritative_answer" => { kind: Bool, derived: false, required: false, description: "Authoritative-answer flag", get |layer| Some(FieldValue::from(layer.authoritative_answer)), set |_layer, _value, name| read_only(dns_schema(), name), layout: (2, 4) },
        "truncated" => { kind: Bool, derived: false, required: false, description: "Truncated response flag", get |layer| Some(FieldValue::from(layer.truncated)), set |_layer, _value, name| read_only(dns_schema(), name), layout: (2, 4) },
        "recursion_desired" => { kind: Bool, derived: false, required: false, description: "Recursion-desired flag", get |layer| Some(FieldValue::from(layer.recursion_desired)), set |_layer, _value, name| read_only(dns_schema(), name), layout: (2, 4) },
        "recursion_available" => { kind: Bool, derived: false, required: false, description: "Recursion-available flag", get |layer| Some(FieldValue::from(layer.recursion_available)), set |_layer, _value, name| read_only(dns_schema(), name), layout: (2, 4) },
        "authenticated_data" => { kind: Bool, derived: false, required: false, description: "Authenticated-data flag", get |layer| Some(FieldValue::from(layer.authenticated_data)), set |_layer, _value, name| read_only(dns_schema(), name), layout: (2, 4) },
        "checking_disabled" => { kind: Bool, derived: false, required: false, description: "Checking-disabled flag", get |layer| Some(FieldValue::from(layer.checking_disabled)), set |_layer, _value, name| read_only(dns_schema(), name), layout: (2, 4) },
        "rcode" => { kind: Unsigned, derived: false, required: false, description: "Response code", get |layer| Some(FieldValue::from(layer.rcode)), set |_layer, _value, name| read_only(dns_schema(), name), layout: (2, 4) },
        "question_count" => { kind: Unsigned, derived: false, required: false, description: "Question count", get |layer| Some(FieldValue::from(layer.question_count)), set |_layer, _value, name| read_only(dns_schema(), name), layout: (4, 6) },
        "answer_count" => { kind: Unsigned, derived: false, required: false, description: "Answer count", get |layer| Some(FieldValue::from(layer.answer_count)), set |_layer, _value, name| read_only(dns_schema(), name), layout: (6, 8) },
        "authority_count" => { kind: Unsigned, derived: false, required: false, description: "Authority-record count", get |layer| Some(FieldValue::from(layer.authority_count)), set |_layer, _value, name| read_only(dns_schema(), name), layout: (8, 10) },
        "additional_count" => { kind: Unsigned, derived: false, required: false, description: "Additional-record count", get |layer| Some(FieldValue::from(layer.additional_count)), set |_layer, _value, name| read_only(dns_schema(), name), layout: (10, 12) },
        "qname" => { kind: List, derived: false, required: false, description: "Question names", get |layer| Some(text_list(&layer.qnames)), set |_layer, _value, name| read_only(dns_schema(), name) },
        "qtype" => { kind: List, derived: false, required: false, description: "Question type codes", get |layer| Some(unsigned_list(&layer.qtypes)), set |_layer, _value, name| read_only(dns_schema(), name) },
        "qclass" => { kind: List, derived: false, required: false, description: "Question class codes", get |layer| Some(unsigned_list(&layer.qclasses)), set |_layer, _value, name| read_only(dns_schema(), name) },
        "answers" => { kind: List, derived: false, required: false, description: "Answer records: [owner, type, class, TTL, RDATA]", get |layer| Some(reflection::records(&layer.answers)), set |_layer, _value, name| read_only(dns_schema(), name) },
        "authorities" => { kind: List, derived: false, required: false, description: "Authority records: [owner, type, class, TTL, RDATA]", get |layer| Some(reflection::records(&layer.authorities)), set |_layer, _value, name| read_only(dns_schema(), name) },
        "additionals" => { kind: List, derived: false, required: false, description: "Additional records including EDNS: [owner, type, class, TTL, RDATA]", get |layer| Some(reflection::records(&layer.additionals)), set |_layer, _value, name| read_only(dns_schema(), name) }
    }
    layout pub(crate) fn dns_layout();
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct DnsCodec;

impl LayerCodec for DnsCodec {
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
        if context.child.is_some() || !payload.is_empty() {
            return Err(invalid(NAME, "DNS is a terminal UDP payload layer"));
        }
        layer.validate_wire_consistency()?;
        ensure_encode_budget(NAME, layer.wire.len(), context)?;
        Ok(
            EncodedLayer::header(layer.wire.to_vec(), Box::new(layer.clone()))
                .with_fields(dns_layout()),
        )
    }

    fn decode(
        &self,
        input: &[u8],
        _context: &LayerDecodeContext<'_>,
    ) -> Result<DecodedLayer, crate::codec::Error> {
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
        _fields: &BTreeMap<String, FieldValue>,
    ) -> Result<Box<dyn Layer>, crate::codec::Error> {
        Err(crate::codec::Error::Unsupported {
            protocol: protocol(NAME),
            message: "DNS is dissection-only; construct a query in the DNS workflow".to_owned(),
        })
    }
}
