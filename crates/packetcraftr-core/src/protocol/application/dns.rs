// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! DNS-over-UDP header and question dissection.

use std::collections::BTreeMap;
use std::fmt::Write as _;

use bytes::Bytes;

use crate::{
    codec::{DecodedLayerValue, EncodedLayer, LayerCodec, LayerDecodeContext, LayerEncodeContext},
    field::FieldValue,
    layer::{Layer, reflective_layer},
};

use crate::protocol::common::{
    ensure_encode_budget, invalid, protocol, read_only, text_list, truncated, typed_layer,
    unsigned_list,
};

use crate::protocol::BuiltinProtocol;

pub mod name;

const NAME: &str = BuiltinProtocol::Dns.as_str();

/// Octets in the fixed DNS message header, before the first question.
pub(crate) const HEADER_LEN: usize = 12;
const MAX_QUESTIONS: usize = 64;
const MAX_NAME_POINTERS: usize = 32;

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
    wire: Bytes,
}

impl Dns {
    /// Parses a DNS message without interpreting resource records.
    pub fn from_wire(wire: impl Into<Bytes>) -> Result<Self, crate::codec::Error> {
        let wire = wire.into();
        let input = wire.as_ref();
        let Some(header) = input.first_chunk::<HEADER_LEN>() else {
            return Err(truncated(NAME, HEADER_LEN, input.len()));
        };
        let flags = u16::from_be_bytes([header[2], header[3]]);
        let question_count = u16::from_be_bytes([header[4], header[5]]);
        let answer_count = u16::from_be_bytes([header[6], header[7]]);
        let authority_count = u16::from_be_bytes([header[8], header[9]]);
        let additional_count = u16::from_be_bytes([header[10], header[11]]);
        let count = usize::from(question_count);
        if count > MAX_QUESTIONS {
            return Err(invalid(
                NAME,
                format!("question count {count} exceeds the limit of {MAX_QUESTIONS}"),
            ));
        }

        let ParsedQuestions {
            qnames,
            qtypes,
            qclasses,
        } = parse_questions(input, count)?;
        Ok(Self {
            id: u16::from_be_bytes([header[0], header[1]]),
            response: flags & 0x8000 != 0,
            opcode: u8::try_from((flags >> 11) & 0x0f)
                .map_err(|_| invalid(NAME, "opcode exceeds four bits"))?,
            authoritative_answer: flags & 0x0400 != 0,
            truncated: flags & 0x0200 != 0,
            recursion_desired: flags & 0x0100 != 0,
            recursion_available: flags & 0x0080 != 0,
            authenticated_data: flags & 0x0020 != 0,
            checking_disabled: flags & 0x0010 != 0,
            rcode: u8::try_from(flags & 0x000f)
                .map_err(|_| invalid(NAME, "rcode exceeds four bits"))?,
            question_count,
            answer_count,
            authority_count,
            additional_count,
            qnames,
            qtypes,
            qclasses,
            wire,
        })
    }

    /// Returns the complete original DNS payload, including opaque records.
    pub fn wire(&self) -> &Bytes {
        &self.wire
    }

    fn validate_wire_consistency(&self) -> Result<(), crate::codec::Error> {
        let parsed = Self::from_wire(self.wire.clone())?;
        if parsed == *self {
            Ok(())
        } else {
            Err(invalid(
                NAME,
                "DNS fields were changed after dissection and no longer match the retained wire payload",
            ))
        }
    }
}

fn read_u16(input: &[u8], cursor: &mut usize) -> Result<u16, crate::codec::Error> {
    let end = checked_end(*cursor, 2)?;
    let bytes = input
        .get(*cursor..end)
        .and_then(<[u8]>::first_chunk::<2>)
        .ok_or_else(|| truncated(NAME, end, input.len()))?;
    *cursor = end;
    Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
}

struct ParsedQuestions {
    qnames: Vec<String>,
    qtypes: Vec<u16>,
    qclasses: Vec<u16>,
}

fn parse_questions(input: &[u8], count: usize) -> Result<ParsedQuestions, crate::codec::Error> {
    let mut cursor = HEADER_LEN;
    let mut qnames = Vec::with_capacity(count);
    let mut qtypes = Vec::with_capacity(count);
    let mut qclasses = Vec::with_capacity(count);
    for _ in 0..count {
        let (next, name) = parse_name(input, cursor)?;
        cursor = next;
        qnames.push(name);
        qtypes.push(read_u16(input, &mut cursor)?);
        qclasses.push(read_u16(input, &mut cursor)?);
    }
    Ok(ParsedQuestions {
        qnames,
        qtypes,
        qclasses,
    })
}

fn checked_end(offset: usize, length: usize) -> Result<usize, crate::codec::Error> {
    offset
        .checked_add(length)
        .ok_or(crate::codec::Error::LengthOverflow {
            protocol: protocol(NAME),
        })
}

fn parse_name(input: &[u8], start: usize) -> Result<(usize, String), crate::codec::Error> {
    let expanded = name::decompress(input, start, MAX_NAME_POINTERS)
        .map_err(|error| name_error(input, error))?;
    Ok((expanded.resume, format_name(&expanded.labels)))
}

/// Restates a decompression failure in this codec's own vocabulary.
fn name_error(input: &[u8], error: name::Error) -> crate::codec::Error {
    match error {
        name::Error::TruncatedLabelLength { offset } => {
            truncated(NAME, offset.saturating_add(1), input.len())
        }
        name::Error::TruncatedPointer { offset } => {
            truncated(NAME, offset.saturating_add(2), input.len())
        }
        name::Error::TruncatedLabel { end, .. } => truncated(NAME, end, input.len()),
        name::Error::PointerOutOfBounds { pointer, .. } => invalid(
            NAME,
            format!("compression pointer {pointer} is outside the message"),
        ),
        name::Error::SelfPointer { offset } => invalid(
            NAME,
            format!("compression pointer {offset} is not backward from {offset}"),
        ),
        name::Error::ForwardPointer { offset, pointer } => invalid(
            NAME,
            format!("compression pointer {pointer} is not backward from {offset}"),
        ),
        name::Error::PointerLoop { offset } => {
            invalid(NAME, format!("compression pointer loop at {offset}"))
        }
        name::Error::PointerLimit { limit } => invalid(
            NAME,
            format!("compression pointer limit of {limit} exceeded"),
        ),
        name::Error::ReservedLabelLength { .. } => invalid(NAME, "reserved label length tag"),
        name::Error::LabelTooLong { actual, .. } => invalid(
            NAME,
            format!("label length {actual} exceeds {}", name::MAX_LABEL_LEN),
        ),
        name::Error::NameTooLong => invalid(
            NAME,
            format!("expanded name exceeds {} wire bytes", name::MAX_NAME_LEN),
        ),
    }
}

fn format_name(labels: &[Bytes]) -> String {
    if labels.is_empty() {
        return ".".to_owned();
    }
    let mut name = String::new();
    for (index, label) in labels.iter().enumerate() {
        if index != 0 {
            name.push('.');
        }
        for byte in label {
            if (0x20..=0x7e).contains(byte) && !matches!(*byte, b'.' | b'\\') {
                name.push(char::from(*byte));
            } else {
                let _ = write!(name, "\\{byte:03}");
            }
        }
    }
    name.push('.');
    name
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
        "qclass" => { kind: List, derived: false, required: false, description: "Question class codes", get |layer| Some(unsigned_list(&layer.qclasses)), set |_layer, _value, name| read_only(dns_schema(), name) }
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
    ) -> Result<DecodedLayerValue, crate::codec::Error> {
        let layer = Dns::from_wire(Bytes::copy_from_slice(input))?;
        Ok(DecodedLayerValue {
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
