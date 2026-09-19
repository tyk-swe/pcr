// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Deterministic, bounded DNS message encoding.

use super::{Dns, NAME, Name, Record, RecordValue};
use crate::codec::{Error, Mode};
use crate::diagnostic::Diagnostic;
use crate::protocol::common::structured::Encoder;
use crate::protocol::common::{ValueExpectation, invalid, resolve_u16};

pub(super) fn message(
    layer: &Dns,
    mode: Mode,
    maximum: usize,
) -> Result<(Vec<u8>, Dns, Vec<Diagnostic>), Error> {
    let maximum = maximum.min(65_535);
    if layer.retained_wire_matches() {
        if layer.wire.len() > maximum {
            return Err(invalid(NAME, "retained DNS message exceeds output budget"));
        }
        return Ok((layer.wire.to_vec(), layer.clone(), Vec::new()));
    }
    if layer.questions.len() > 64
        || layer
            .answers
            .len()
            .saturating_add(layer.authorities.len())
            .saturating_add(layer.additionals.len())
            > 4096
    {
        return Err(invalid(NAME, "DNS question or record limit exceeded"));
    }
    if layer.opcode > 15 || layer.rcode > 15 {
        return Err(invalid(NAME, "DNS opcode and rcode must fit four bits"));
    }
    let mut result = layer.clone();
    let mut diagnostics = Vec::new();
    let mut output = Encoder::new(NAME, maximum);
    output.u16(layer.id)?;
    let flags = u16::from(layer.response) << 15
        | u16::from(layer.opcode) << 11
        | u16::from(layer.authoritative_answer) << 10
        | u16::from(layer.truncated) << 9
        | u16::from(layer.recursion_desired) << 8
        | u16::from(layer.recursion_available) << 7
        | u16::from(layer.reserved) << 6
        | u16::from(layer.authenticated_data) << 5
        | u16::from(layer.checking_disabled) << 4
        | u16::from(layer.rcode);
    output.u16(flags)?;
    for (name, requested, actual, resolved) in [
        (
            "question_count",
            &layer.question_count,
            layer.questions.len(),
            &mut result.question_count,
        ),
        (
            "answer_count",
            &layer.answer_count,
            layer.answers.len(),
            &mut result.answer_count,
        ),
        (
            "authority_count",
            &layer.authority_count,
            layer.authorities.len(),
            &mut result.authority_count,
        ),
        (
            "additional_count",
            &layer.additional_count,
            layer.additionals.len(),
            &mut result.additional_count,
        ),
    ] {
        let count =
            u16::try_from(actual).map_err(|_| invalid(NAME, "DNS section count overflow"))?;
        let (wire, materialized) = resolve_u16(
            NAME,
            name,
            requested,
            ValueExpectation::Required(count),
            mode,
            &mut diagnostics,
        )?;
        *resolved = materialized;
        output.u16(wire)?;
    }
    for question in &layer.questions {
        name(&mut output, &question.name)?;
        output.u16(question.query_type)?;
        output.u16(question.class)?;
    }
    for record in layer
        .answers
        .iter()
        .chain(&layer.authorities)
        .chain(&layer.additionals)
    {
        encode_record(&mut output, record, maximum)?;
    }
    Ok((output.finish(), result, diagnostics))
}

fn name(output: &mut Encoder, value: &Name) -> Result<(), Error> {
    for label in value.labels() {
        output.u8(u8::try_from(label.len()).map_err(|_| invalid(NAME, "DNS label overflow"))?)?;
        output.bytes(label)?;
    }
    output.u8(0)
}

fn encode_record(output: &mut Encoder, record: &Record, maximum: usize) -> Result<(), Error> {
    name(output, &record.owner)?;
    output.u16(record.value.type_code())?;
    let (class, ttl) = match &record.value {
        RecordValue::Opt(edns) => {
            if record.class != edns.udp_payload_size
                || record.ttl != edns.record_ttl()
                || (edns.flags & 0x8000 != 0) != edns.dnssec_ok
            {
                return Err(invalid(
                    NAME,
                    "OPT record class/TTL and EDNS fields disagree",
                ));
            }
            (record.class, record.ttl)
        }
        _ => (record.class, record.ttl),
    };
    output.u16(class)?;
    output.u32(ttl)?;
    let mut data = Encoder::new(NAME, maximum);
    match &record.value {
        RecordValue::A(address) => data.bytes(&address.octets())?,
        RecordValue::Aaaa(address) => data.bytes(&address.octets())?,
        RecordValue::Cname(value) | RecordValue::Ns(value) | RecordValue::Ptr(value) => {
            name(&mut data, value)?;
        }
        RecordValue::Mx {
            preference,
            exchange,
        } => {
            data.u16(*preference)?;
            name(&mut data, exchange)?;
        }
        RecordValue::Soa {
            primary_name_server,
            responsible_mailbox,
            serial,
            refresh,
            retry,
            expire,
            minimum,
        } => {
            name(&mut data, primary_name_server)?;
            name(&mut data, responsible_mailbox)?;
            for value in [serial, refresh, retry, expire, minimum] {
                data.u32(*value)?;
            }
        }
        RecordValue::Srv {
            priority,
            weight,
            port,
            target,
        } => {
            for value in [priority, weight, port] {
                data.u16(*value)?;
            }
            name(&mut data, target)?;
        }
        RecordValue::Caa { flags, tag, value } => {
            data.u8(*flags)?;
            data.u8(
                u8::try_from(tag.len()).map_err(|_| invalid(NAME, "CAA tag exceeds 255 bytes"))?
            )?;
            data.bytes(tag)?;
            data.bytes(value)?;
        }
        RecordValue::Txt(strings) => {
            if strings.len() > 4096 {
                return Err(invalid(NAME, "TXT string count exceeded"));
            }
            for string in strings {
                data.u8(u8::try_from(string.len())
                    .map_err(|_| invalid(NAME, "TXT string exceeds 255 bytes"))?)?;
                data.bytes(string)?;
            }
        }
        RecordValue::Opt(edns) => {
            if edns.options.len() > 4096 {
                return Err(invalid(NAME, "EDNS option count exceeded"));
            }
            for option in &edns.options {
                data.u16(option.code)?;
                data.u16(
                    u16::try_from(option.data.len())
                        .map_err(|_| invalid(NAME, "EDNS option exceeds wire length"))?,
                )?;
                data.bytes(&option.data)?;
            }
        }
        RecordValue::Unknown { rdata, .. } => data.bytes(rdata)?,
    }
    let data = data.finish();
    output.u16(
        u16::try_from(data.len()).map_err(|_| invalid(NAME, "DNS RDATA exceeds wire length"))?,
    )?;
    output.bytes(&data)
}
