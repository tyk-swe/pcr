// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! DNS-over-UDP header and question dissection.

use std::collections::BTreeMap;
use std::fmt::Write as _;

use bytes::Bytes;

use packetcraftr_packet::{
    codec::{
        CodecError, DecodedLayerValue, EncodedLayer, LayerCodec, LayerDecodeContext,
        LayerEncodeContext,
    },
    field::FieldValue,
    layer::{FieldError, Layer, ProtocolId, reflective_layer},
};

use super::super::common::{ensure_encode_budget, invalid, protocol, truncated, wrong_layer};

const DNS_HEADER_LEN: usize = 12;
const MAX_QUESTIONS: usize = 64;
const MAX_NAME_POINTERS: usize = 32;
const MAX_EXPANDED_NAME_LEN: usize = 255;
const MAX_LABEL_LEN: usize = 63;

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
    pub fn from_wire(wire: impl Into<Bytes>) -> Result<Self, CodecError> {
        let wire = wire.into();
        let input = wire.as_ref();
        let header = input
            .get(..DNS_HEADER_LEN)
            .ok_or_else(|| truncated("dns", DNS_HEADER_LEN, input.len()))?;
        let flags = u16::from_be_bytes([header[2], header[3]]);
        let question_count = u16::from_be_bytes([header[4], header[5]]);
        let answer_count = u16::from_be_bytes([header[6], header[7]]);
        let authority_count = u16::from_be_bytes([header[8], header[9]]);
        let additional_count = u16::from_be_bytes([header[10], header[11]]);
        let count = usize::from(question_count);
        if count > MAX_QUESTIONS {
            return Err(invalid(
                "dns",
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
                .map_err(|_| invalid("dns", "opcode exceeds four bits"))?,
            authoritative_answer: flags & 0x0400 != 0,
            truncated: flags & 0x0200 != 0,
            recursion_desired: flags & 0x0100 != 0,
            recursion_available: flags & 0x0080 != 0,
            authenticated_data: flags & 0x0020 != 0,
            checking_disabled: flags & 0x0010 != 0,
            rcode: u8::try_from(flags & 0x000f)
                .map_err(|_| invalid("dns", "rcode exceeds four bits"))?,
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

    fn validate_wire_consistency(&self) -> Result<(), CodecError> {
        let parsed = Self::from_wire(self.wire.clone())?;
        if parsed == *self {
            Ok(())
        } else {
            Err(invalid(
                "dns",
                "DNS fields were changed after dissection and no longer match the retained wire payload",
            ))
        }
    }
}

fn read_u16(input: &[u8], cursor: &mut usize) -> Result<u16, CodecError> {
    let bytes = take(input, *cursor, 2)?;
    *cursor = checked_end(*cursor, 2)?;
    Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
}

struct ParsedQuestions {
    qnames: Vec<String>,
    qtypes: Vec<u16>,
    qclasses: Vec<u16>,
}

fn parse_questions(input: &[u8], count: usize) -> Result<ParsedQuestions, CodecError> {
    let mut cursor = DNS_HEADER_LEN;
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

fn checked_end(offset: usize, length: usize) -> Result<usize, CodecError> {
    offset
        .checked_add(length)
        .ok_or(CodecError::LengthOverflow {
            protocol: protocol("dns"),
        })
}

fn take(input: &[u8], offset: usize, length: usize) -> Result<&[u8], CodecError> {
    let end = checked_end(offset, length)?;
    input
        .get(offset..end)
        .ok_or_else(|| truncated("dns", end, input.len()))
}

fn parse_name(input: &[u8], start: usize) -> Result<(usize, String), CodecError> {
    let mut cursor = start;
    let mut resume = None;
    let mut labels = Vec::new();
    let mut visited = Vec::new();
    let mut expanded_len = 1usize;

    loop {
        let length_end = checked_end(cursor, 1)?;
        let length = *input
            .get(cursor)
            .ok_or_else(|| truncated("dns", length_end, input.len()))?;
        match length & 0xc0 {
            0xc0 => {
                let pointer_end = checked_end(cursor, 2)?;
                let second_offset = checked_end(cursor, 1)?;
                let second = *input
                    .get(second_offset)
                    .ok_or_else(|| truncated("dns", pointer_end, input.len()))?;
                let pointer = (usize::from(length & 0x3f) << 8) | usize::from(second);
                if pointer >= input.len() {
                    return Err(invalid(
                        "dns",
                        format!("compression pointer {pointer} is outside the message"),
                    ));
                }
                if pointer >= cursor {
                    return Err(invalid(
                        "dns",
                        format!("compression pointer {pointer} is not backward from {cursor}"),
                    ));
                }
                if visited.len() >= MAX_NAME_POINTERS {
                    return Err(invalid(
                        "dns",
                        format!("compression pointer limit of {MAX_NAME_POINTERS} exceeded"),
                    ));
                }
                if visited.contains(&pointer) {
                    return Err(invalid(
                        "dns",
                        format!("compression pointer loop at {pointer}"),
                    ));
                }
                visited.push(pointer);
                resume.get_or_insert(pointer_end);
                cursor = pointer;
            }
            0 => {
                cursor = length_end;
                if length == 0 {
                    let next = resume.unwrap_or(cursor);
                    return Ok((next, format_name(&labels)));
                }
                let label_len = usize::from(length);
                if label_len > MAX_LABEL_LEN {
                    return Err(invalid(
                        "dns",
                        format!("label length {label_len} exceeds {MAX_LABEL_LEN}"),
                    ));
                }
                let label = take(input, cursor, label_len)?;
                expanded_len =
                    expanded_len
                        .checked_add(label_len + 1)
                        .ok_or(CodecError::LengthOverflow {
                            protocol: protocol("dns"),
                        })?;
                if expanded_len > MAX_EXPANDED_NAME_LEN {
                    return Err(invalid(
                        "dns",
                        format!("expanded name exceeds {MAX_EXPANDED_NAME_LEN} wire bytes"),
                    ));
                }
                labels.push(label.to_vec());
                cursor = checked_end(cursor, label_len)?;
            }
            _ => {
                return Err(invalid("dns", "reserved label length tag"));
            }
        }
    }
}

fn format_name(labels: &[Vec<u8>]) -> String {
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

fn readonly(field: &str) -> Result<(), FieldError> {
    Err(FieldError::ReadOnly {
        protocol: dns_schema().protocol.clone(),
        field: field.to_owned(),
    })
}

fn text_list(values: &[String]) -> FieldValue {
    FieldValue::List(values.iter().cloned().map(FieldValue::Text).collect())
}

fn unsigned_list(values: &[u16]) -> FieldValue {
    FieldValue::List(values.iter().copied().map(FieldValue::from).collect())
}

reflective_layer! {
    fn dns_schema() => { protocol: protocol("dns"), name: "DNS" }
    impl Dns {
        "id" => { kind: Unsigned, derived: false, required: false, description: "Transaction identifier", get |layer| Some(FieldValue::from(layer.id)), set |_layer, _value, name| readonly(name), layout: (0, 2) },
        "response" => { kind: Bool, derived: false, required: false, description: "Query/response flag", get |layer| Some(FieldValue::from(layer.response)), set |_layer, _value, name| readonly(name), layout: (2, 4) },
        "opcode" => { kind: Unsigned, derived: false, required: false, description: "Operation code", get |layer| Some(FieldValue::from(layer.opcode)), set |_layer, _value, name| readonly(name), layout: (2, 4) },
        "authoritative_answer" => { kind: Bool, derived: false, required: false, description: "Authoritative-answer flag", get |layer| Some(FieldValue::from(layer.authoritative_answer)), set |_layer, _value, name| readonly(name), layout: (2, 4) },
        "truncated" => { kind: Bool, derived: false, required: false, description: "Truncated response flag", get |layer| Some(FieldValue::from(layer.truncated)), set |_layer, _value, name| readonly(name), layout: (2, 4) },
        "recursion_desired" => { kind: Bool, derived: false, required: false, description: "Recursion-desired flag", get |layer| Some(FieldValue::from(layer.recursion_desired)), set |_layer, _value, name| readonly(name), layout: (2, 4) },
        "recursion_available" => { kind: Bool, derived: false, required: false, description: "Recursion-available flag", get |layer| Some(FieldValue::from(layer.recursion_available)), set |_layer, _value, name| readonly(name), layout: (2, 4) },
        "authenticated_data" => { kind: Bool, derived: false, required: false, description: "Authenticated-data flag", get |layer| Some(FieldValue::from(layer.authenticated_data)), set |_layer, _value, name| readonly(name), layout: (2, 4) },
        "checking_disabled" => { kind: Bool, derived: false, required: false, description: "Checking-disabled flag", get |layer| Some(FieldValue::from(layer.checking_disabled)), set |_layer, _value, name| readonly(name), layout: (2, 4) },
        "rcode" => { kind: Unsigned, derived: false, required: false, description: "Response code", get |layer| Some(FieldValue::from(layer.rcode)), set |_layer, _value, name| readonly(name), layout: (2, 4) },
        "question_count" => { kind: Unsigned, derived: false, required: false, description: "Question count", get |layer| Some(FieldValue::from(layer.question_count)), set |_layer, _value, name| readonly(name), layout: (4, 6) },
        "answer_count" => { kind: Unsigned, derived: false, required: false, description: "Answer count", get |layer| Some(FieldValue::from(layer.answer_count)), set |_layer, _value, name| readonly(name), layout: (6, 8) },
        "authority_count" => { kind: Unsigned, derived: false, required: false, description: "Authority-record count", get |layer| Some(FieldValue::from(layer.authority_count)), set |_layer, _value, name| readonly(name), layout: (8, 10) },
        "additional_count" => { kind: Unsigned, derived: false, required: false, description: "Additional-record count", get |layer| Some(FieldValue::from(layer.additional_count)), set |_layer, _value, name| readonly(name), layout: (10, 12) },
        "qname" => { kind: List, derived: false, required: false, description: "Question names", get |layer| Some(text_list(&layer.qnames)), set |_layer, _value, name| readonly(name) },
        "qtype" => { kind: List, derived: false, required: false, description: "Question type codes", get |layer| Some(unsigned_list(&layer.qtypes)), set |_layer, _value, name| readonly(name) },
        "qclass" => { kind: List, derived: false, required: false, description: "Question class codes", get |layer| Some(unsigned_list(&layer.qclasses)), set |_layer, _value, name| readonly(name) }
    }
    layout pub(crate) fn dns_layout();
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct DnsCodec;

impl LayerCodec for DnsCodec {
    fn protocol_id(&self) -> ProtocolId {
        protocol("dns")
    }

    fn aliases(&self) -> &'static [&'static str] {
        super::super::support::aliases(self.protocol_id().as_str())
    }

    fn published_schema(&self) -> Option<&'static packetcraftr_packet::layer::LayerSchema> {
        Some(dns_schema())
    }

    fn encode(
        &self,
        layer: &dyn Layer,
        payload: &[u8],
        context: &LayerEncodeContext<'_>,
    ) -> Result<EncodedLayer, CodecError> {
        let layer = layer
            .as_any()
            .downcast_ref::<Dns>()
            .ok_or_else(|| wrong_layer("dns", layer))?;
        if context.child.is_some() || !payload.is_empty() {
            return Err(invalid("dns", "DNS is a terminal UDP payload layer"));
        }
        layer.validate_wire_consistency()?;
        ensure_encode_budget("dns", layer.wire.len(), context)?;
        Ok(EncodedLayer {
            prefix: layer.wire.to_vec(),
            suffix: Vec::new(),
            materialized: Box::new(layer.clone()),
            fields: dns_layout(),
            diagnostics: Vec::new(),
        })
    }

    fn decode(
        &self,
        input: &[u8],
        _context: &LayerDecodeContext<'_>,
    ) -> Result<DecodedLayerValue, CodecError> {
        let layer = Dns::from_wire(Bytes::copy_from_slice(input))?;
        Ok(DecodedLayerValue {
            layer: Box::new(layer),
            consumed: input.len(),
            payload_offset: input.len(),
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
    ) -> Result<Box<dyn Layer>, CodecError> {
        Err(CodecError::Unsupported {
            protocol: protocol("dns"),
            message: "DNS is dissection-only; construct a query in the DNS workflow".to_owned(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn query() -> Bytes {
        Bytes::from_static(&[
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 3, b'W', b'w',
            b'W', 7, b'E', b'x', b'a', b'm', b'P', b'L', b'E', 0, 0, 1, 0, 1,
        ])
    }

    #[test]
    fn parses_bounded_header_and_questions_without_losing_wire_bytes() {
        let wire = query();
        let dns = Dns::from_wire(wire.clone()).unwrap();
        assert_eq!(dns.id, 0x1234);
        assert_eq!(dns.qnames, vec!["WwW.ExamPLE."]);
        assert_eq!(dns.qtypes, vec![1]);
        assert_eq!(dns.qclasses, vec![1]);
        assert_eq!(dns.wire(), &wire);
        assert_eq!(
            dns.field("qname"),
            Some(FieldValue::List(vec![FieldValue::Text(
                "WwW.ExamPLE.".to_owned()
            )]))
        );
    }

    #[test]
    fn rejects_forward_pointers_and_oversized_question_lists() {
        let mut forward = query().to_vec();
        forward[12] = 0xc0;
        forward[13] = 0xff;
        assert!(matches!(
            Dns::from_wire(forward),
            Err(CodecError::Invalid { .. })
        ));

        let mut many = vec![0; DNS_HEADER_LEN];
        many[4..6].copy_from_slice(&65_u16.to_be_bytes());
        assert!(matches!(
            Dns::from_wire(many),
            Err(CodecError::Invalid { .. })
        ));
    }

    #[test]
    fn rejects_fields_that_diverge_from_retained_wire_bytes() {
        let mut dns = Dns::from_wire(query()).unwrap();
        dns.id ^= 1;

        assert!(matches!(
            dns.validate_wire_consistency(),
            Err(CodecError::Invalid { .. })
        ));
    }

    #[test]
    fn enforces_truncation_label_name_and_pointer_bounds() {
        assert!(matches!(
            Dns::from_wire(Bytes::new()),
            Err(CodecError::Truncated { .. })
        ));

        let mut long_label = vec![0; DNS_HEADER_LEN];
        long_label[4..6].copy_from_slice(&1_u16.to_be_bytes());
        long_label.push(64);
        assert!(Dns::from_wire(long_label).is_err());

        let mut long_name = vec![0; DNS_HEADER_LEN];
        long_name[4..6].copy_from_slice(&1_u16.to_be_bytes());
        long_name.push(63);
        long_name.extend(std::iter::repeat_n(b'a', 63));
        long_name.push(63);
        long_name.extend(std::iter::repeat_n(b'b', 63));
        long_name.push(63);
        long_name.extend(std::iter::repeat_n(b'c', 63));
        long_name.push(63);
        long_name.extend(std::iter::repeat_n(b'd', 63));
        long_name.push(0);
        assert!(matches!(
            Dns::from_wire(long_name),
            Err(CodecError::Invalid { .. })
        ));

        let base = 64;
        let pointer_count = MAX_NAME_POINTERS + 1;
        let start = base + pointer_count * 2;
        let mut pointers = vec![0; start + 2];
        for index in 0..pointer_count {
            let offset = base + index * 2;
            let target = if index == 0 { 0 } else { offset - 2 };
            pointers[offset..offset + 2]
                .copy_from_slice(&(0xc000_u16 | u16::try_from(target).unwrap()).to_be_bytes());
        }
        pointers[start..start + 2]
            .copy_from_slice(&(0xc000_u16 | u16::try_from(start - 2).unwrap()).to_be_bytes());
        assert!(matches!(
            parse_name(&pointers, start),
            Err(CodecError::Invalid { .. })
        ));
    }
}
