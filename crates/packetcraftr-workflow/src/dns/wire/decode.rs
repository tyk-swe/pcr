// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::{Ipv4Addr, Ipv6Addr};

use bytes::Bytes;

use super::super::error::DnsWireError;
use super::super::model::{
    DnsEdns, DnsEdnsOption, DnsLimits, DnsName, DnsQueryType, DnsRecord, DnsRecordValue,
    ValidatedDnsResponse,
};
use super::super::{
    DNS_CLASS_IN, DNS_FLAG_AUTHENTICATED_DATA, DNS_FLAG_AUTHORITATIVE, DNS_FLAG_CHECKING_DISABLED,
    DNS_FLAG_RECURSION_AVAILABLE, DNS_FLAG_RECURSION_DESIRED, DNS_FLAG_RESPONSE,
    DNS_FLAG_TRUNCATED, DNS_HEADER_BYTES, DNS_OPCODE_MASK, DNS_RCODE_MASK, DNS_RESERVED_MASK,
    DNS_TYPE_OPT,
};
use super::name::{canonical_query_name, decode_name};
use super::relevance::{RelevantRecords, filter_relevant_records};

/// Decodes the length prefix of a single DNS-over-TCP frame, then applies the
/// same transaction, question, bounds, and relevance validation as UDP.
pub fn decode_dns_tcp_frame(
    frame: &[u8],
    query_name: &str,
    query_type: DnsQueryType,
    transaction_id: u16,
    limits: DnsLimits,
) -> Result<ValidatedDnsResponse, DnsWireError> {
    let prefix = frame.get(..2).ok_or(DnsWireError::MessageTooShort {
        actual: frame.len(),
        minimum: 2,
    })?;
    let declared = usize::from(u16::from_be_bytes([prefix[0], prefix[1]]));
    let payload = &frame[2..];
    if declared != payload.len() {
        return Err(DnsWireError::TcpFrameLength {
            declared,
            actual: payload.len(),
        });
    }
    decode_dns_response(payload, query_name, query_type, transaction_id, limits)
}

/// Decodes and validates one complete DNS response. Only records relevant to
/// the validated question are returned as accepted section data; all other
/// declared records contribute to a bounded rejected-record audit trail.
pub fn decode_dns_response(
    message: &[u8],
    query_name: &str,
    query_type: DnsQueryType,
    transaction_id: u16,
    limits: DnsLimits,
) -> Result<ValidatedDnsResponse, DnsWireError> {
    let query_name = canonical_query_name(query_name)?;
    let expected_name = DnsName::from_canonical_ascii(&query_name);
    if message.len() < DNS_HEADER_BYTES {
        return Err(DnsWireError::MessageTooShort {
            actual: message.len(),
            minimum: DNS_HEADER_BYTES,
        });
    }
    if message.len() > limits.max_message_bytes {
        return Err(DnsWireError::MessageTooLarge {
            actual: message.len(),
            maximum: limits.max_message_bytes,
        });
    }

    let actual_id = read_u16(message, 0, "transaction ID")?;
    let flags = read_u16(message, 2, "flags")?;
    if flags & DNS_FLAG_RESPONSE == 0 {
        return Err(DnsWireError::NotResponse);
    }
    let opcode = ((flags & DNS_OPCODE_MASK) >> 11) as u8;
    if opcode != 0 {
        return Err(DnsWireError::UnsupportedOpcode { opcode });
    }
    if flags & DNS_RESERVED_MASK != 0 {
        return Err(DnsWireError::ReservedHeaderBits);
    }
    if actual_id != transaction_id {
        return Err(DnsWireError::TransactionIdMismatch {
            expected: transaction_id,
            actual: actual_id,
        });
    }
    let question_count = read_u16(message, 4, "question count")?;
    if question_count != 1 {
        return Err(DnsWireError::QuestionCount {
            actual: question_count,
        });
    }
    let answer_count = usize::from(read_u16(message, 6, "answer count")?);
    let authority_count = usize::from(read_u16(message, 8, "authority count")?);
    let additional_count = usize::from(read_u16(message, 10, "additional count")?);
    let (actual_name, mut offset) = decode_name(message, DNS_HEADER_BYTES, limits)?;
    if actual_name != expected_name {
        return Err(DnsWireError::QuestionNameMismatch {
            expected: query_name,
            actual: actual_name.to_string(),
        });
    }
    let actual_type = read_u16(message, offset, "question type")?;
    offset += 2;
    if actual_type != query_type.code() {
        return Err(DnsWireError::QuestionTypeMismatch {
            expected: query_type.code(),
            actual: actual_type,
        });
    }
    let actual_class = read_u16(message, offset, "question class")?;
    offset += 2;
    if actual_class != DNS_CLASS_IN {
        return Err(DnsWireError::QuestionClassMismatch {
            actual: actual_class,
        });
    }

    let truncated = flags & DNS_FLAG_TRUNCATED != 0;
    if truncated {
        // A UDP truncation may end at any byte after the complete question.
        // Do not decode or present possibly partial records as accepted facts.
        return Ok(ValidatedDnsResponse {
            transaction_id,
            response_code: flags & DNS_RCODE_MASK,
            edns: None,
            authoritative: flags & DNS_FLAG_AUTHORITATIVE != 0,
            truncated: true,
            recursion_desired: flags & DNS_FLAG_RECURSION_DESIRED != 0,
            recursion_available: flags & DNS_FLAG_RECURSION_AVAILABLE != 0,
            authenticated_data: flags & DNS_FLAG_AUTHENTICATED_DATA != 0,
            checking_disabled: flags & DNS_FLAG_CHECKING_DISABLED != 0,
            answers: Vec::new(),
            authorities: Vec::new(),
            additionals: Vec::new(),
            rejected_records: Vec::new(),
            rejected_record_count: 0,
        });
    }

    let record_count = answer_count
        .checked_add(authority_count)
        .and_then(|count| count.checked_add(additional_count))
        .ok_or(DnsWireError::RecordLimit {
            actual: usize::MAX,
            limit: limits.max_records,
        })?;
    if record_count > limits.max_records {
        return Err(DnsWireError::RecordLimit {
            actual: record_count,
            limit: limits.max_records,
        });
    }

    let (answers, next) = decode_records(message, offset, answer_count, limits)?;
    let (authorities, next) = decode_records(message, next, authority_count, limits)?;
    let (additionals, next) = decode_records(message, next, additional_count, limits)?;
    if next != message.len() {
        return Err(DnsWireError::TrailingBytes {
            remaining: message.len() - next,
        });
    }
    if answers
        .iter()
        .chain(&authorities)
        .any(|record| matches!(record.value, DnsRecordValue::Opt(_)))
    {
        return Err(DnsWireError::InvalidEdns {
            message: "OPT pseudo-record must appear only in the additional section".to_owned(),
        });
    }
    let mut edns = None;
    let mut non_opt_additionals = Vec::with_capacity(additionals.len());
    for record in additionals {
        match &record.value {
            DnsRecordValue::Opt(value) => {
                if !record.owner.is_root() {
                    return Err(DnsWireError::InvalidEdns {
                        message: "OPT owner name must be the root".to_owned(),
                    });
                }
                if edns.replace(value.clone()).is_some() {
                    return Err(DnsWireError::DuplicateEdns);
                }
            }
            _ => non_opt_additionals.push(record),
        }
    }
    let response_code = (edns
        .as_ref()
        .map_or(0, |edns| u16::from(edns.extended_response_code))
        << 4)
        | (flags & DNS_RCODE_MASK);
    let RelevantRecords {
        answers,
        authorities,
        additionals,
        rejected_records,
        rejected_record_count,
    } = filter_relevant_records(
        &expected_name,
        query_type,
        answers,
        authorities,
        non_opt_additionals,
        limits.max_rejected_records,
    );
    Ok(ValidatedDnsResponse {
        transaction_id,
        response_code,
        edns,
        authoritative: flags & DNS_FLAG_AUTHORITATIVE != 0,
        truncated: false,
        recursion_desired: flags & DNS_FLAG_RECURSION_DESIRED != 0,
        recursion_available: flags & DNS_FLAG_RECURSION_AVAILABLE != 0,
        authenticated_data: flags & DNS_FLAG_AUTHENTICATED_DATA != 0,
        checking_disabled: flags & DNS_FLAG_CHECKING_DISABLED != 0,
        answers,
        authorities,
        additionals,
        rejected_records,
        rejected_record_count,
    })
}

fn read_u16(message: &[u8], offset: usize, field: &'static str) -> Result<u16, DnsWireError> {
    let bytes = message
        .get(offset..offset.saturating_add(2))
        .ok_or(DnsWireError::TruncatedField { field, offset })?;
    Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
}

fn read_u32(message: &[u8], offset: usize, field: &'static str) -> Result<u32, DnsWireError> {
    let bytes = message
        .get(offset..offset.saturating_add(4))
        .ok_or(DnsWireError::TruncatedField { field, offset })?;
    Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn decode_records(
    message: &[u8],
    mut offset: usize,
    count: usize,
    limits: DnsLimits,
) -> Result<(Vec<DnsRecord>, usize), DnsWireError> {
    let mut records = Vec::with_capacity(count);
    for _ in 0..count {
        let (owner, next) = decode_name(message, offset, limits)?;
        offset = next;
        let type_code = read_u16(message, offset, "record type")?;
        let class = read_u16(message, offset + 2, "record class")?;
        let ttl = read_u32(message, offset + 4, "record TTL")?;
        let rdata_length = usize::from(read_u16(message, offset + 8, "RDATA length")?);
        let rdata_offset = offset + 10;
        let rdata_end =
            rdata_offset
                .checked_add(rdata_length)
                .ok_or(DnsWireError::TruncatedField {
                    field: "RDATA",
                    offset: rdata_offset,
                })?;
        message
            .get(rdata_offset..rdata_end)
            .ok_or(DnsWireError::TruncatedField {
                field: "RDATA",
                offset: rdata_offset,
            })?;
        let value = decode_rdata(
            message,
            type_code,
            class,
            ttl,
            rdata_offset,
            rdata_end,
            limits,
        )?;
        records.push(DnsRecord {
            owner,
            class,
            ttl,
            value,
        });
        offset = rdata_end;
    }
    Ok((records, offset))
}

fn decode_rdata(
    message: &[u8],
    type_code: u16,
    class: u16,
    ttl: u32,
    offset: usize,
    end: usize,
    limits: DnsLimits,
) -> Result<DnsRecordValue, DnsWireError> {
    let rdata = message
        .get(offset..end)
        .ok_or(DnsWireError::TruncatedField {
            field: "RDATA",
            offset,
        })?;
    let invalid = |message: &str| DnsWireError::InvalidRdata {
        record_type: type_code,
        offset,
        message: message.to_owned(),
    };
    let exact_name = |start| -> Result<DnsName, DnsWireError> {
        let (name, next) = decode_name(message, start, limits)?;
        if next != end {
            return Err(invalid("name does not consume the declared RDATA"));
        }
        Ok(name)
    };
    match type_code {
        1 => {
            let bytes: [u8; 4] = rdata
                .try_into()
                .map_err(|_| invalid("A RDATA must be 4 bytes"))?;
            Ok(DnsRecordValue::A(Ipv4Addr::from(bytes)))
        }
        2 => Ok(DnsRecordValue::Ns(exact_name(offset)?)),
        5 => Ok(DnsRecordValue::Cname(exact_name(offset)?)),
        6 => {
            let (primary_name_server, next) = decode_name(message, offset, limits)?;
            let (responsible_mailbox, next) = decode_name(message, next, limits)?;
            if next.checked_add(20) != Some(end) {
                return Err(invalid("SOA RDATA must end with five 32-bit integers"));
            }
            Ok(DnsRecordValue::Soa {
                primary_name_server,
                responsible_mailbox,
                serial: read_u32(message, next, "SOA serial")?,
                refresh: read_u32(message, next + 4, "SOA refresh")?,
                retry: read_u32(message, next + 8, "SOA retry")?,
                expire: read_u32(message, next + 12, "SOA expire")?,
                minimum: read_u32(message, next + 16, "SOA minimum")?,
            })
        }
        12 => Ok(DnsRecordValue::Ptr(exact_name(offset)?)),
        15 => {
            if rdata.len() < 3 {
                return Err(invalid("MX RDATA is shorter than preference plus name"));
            }
            let preference = read_u16(message, offset, "MX preference")?;
            let (exchange, next) = decode_name(message, offset + 2, limits)?;
            if next != end {
                return Err(invalid("MX name does not consume the declared RDATA"));
            }
            Ok(DnsRecordValue::Mx {
                preference,
                exchange,
            })
        }
        16 => {
            let mut cursor = 0usize;
            let mut strings = Vec::new();
            let mut total = 0usize;
            while cursor < rdata.len() {
                if strings.len() >= limits.max_txt_strings {
                    return Err(DnsWireError::TxtStringLimit {
                        limit: limits.max_txt_strings,
                    });
                }
                let length = usize::from(rdata[cursor]);
                cursor += 1;
                let string = rdata
                    .get(cursor..cursor.saturating_add(length))
                    .ok_or_else(|| invalid("TXT character-string exceeds declared RDATA"))?;
                total = total
                    .checked_add(length)
                    .ok_or(DnsWireError::TxtByteLimit {
                        limit: limits.max_txt_bytes,
                    })?;
                if total > limits.max_txt_bytes {
                    return Err(DnsWireError::TxtByteLimit {
                        limit: limits.max_txt_bytes,
                    });
                }
                strings.push(Bytes::copy_from_slice(string));
                cursor += length;
            }
            Ok(DnsRecordValue::Txt(strings))
        }
        28 => {
            let bytes: [u8; 16] = rdata
                .try_into()
                .map_err(|_| invalid("AAAA RDATA must be 16 bytes"))?;
            Ok(DnsRecordValue::Aaaa(Ipv6Addr::from(bytes)))
        }
        33 => {
            if rdata.len() < 7 {
                return Err(invalid(
                    "SRV RDATA is shorter than priority, weight, port, and name",
                ));
            }
            let priority = read_u16(message, offset, "SRV priority")?;
            let weight = read_u16(message, offset + 2, "SRV weight")?;
            let port = read_u16(message, offset + 4, "SRV port")?;
            let (target, next) = decode_name(message, offset + 6, limits)?;
            if next != end {
                return Err(invalid("SRV name does not consume the declared RDATA"));
            }
            Ok(DnsRecordValue::Srv {
                priority,
                weight,
                port,
                target,
            })
        }
        DNS_TYPE_OPT => decode_edns(class, ttl, rdata).map(DnsRecordValue::Opt),
        _ => Ok(DnsRecordValue::Unknown {
            type_code,
            rdata: Bytes::copy_from_slice(rdata),
        }),
    }
}

fn decode_edns(class: u16, ttl: u32, rdata: &[u8]) -> Result<DnsEdns, DnsWireError> {
    let extended_response_code = (ttl >> 24) as u8;
    let version = ((ttl >> 16) & 0xff) as u8;
    if version != 0 {
        return Err(DnsWireError::UnsupportedEdnsVersion { version });
    }
    #[expect(
        clippy::cast_possible_truncation,
        reason = "an OPT record packs the extended rcode and version in the high half of the TTL \
                  field; the low 16 bits are the flags this reads"
    )]
    let flags = ttl as u16;
    let mut options = Vec::new();
    let mut cursor = 0usize;
    while cursor < rdata.len() {
        let header = rdata.get(cursor..cursor.saturating_add(4)).ok_or_else(|| {
            DnsWireError::InvalidEdns {
                message: format!("option header is truncated at RDATA byte {cursor}"),
            }
        })?;
        let code = u16::from_be_bytes([header[0], header[1]]);
        let length = usize::from(u16::from_be_bytes([header[2], header[3]]));
        cursor += 4;
        let data = rdata
            .get(cursor..cursor.saturating_add(length))
            .ok_or_else(|| DnsWireError::InvalidEdns {
                message: format!("option {code} data is truncated"),
            })?;
        options.push(DnsEdnsOption {
            code,
            data: Bytes::copy_from_slice(data),
        });
        cursor += length;
    }
    Ok(DnsEdns {
        udp_payload_size: class,
        extended_response_code,
        version,
        dnssec_ok: flags & 0x8000 != 0,
        flags,
        options,
    })
}
