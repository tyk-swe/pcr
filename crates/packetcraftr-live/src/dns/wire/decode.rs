// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Ordered DNS response validation and decoding orchestration.

use super::super::error::DnsWireError;
use super::super::model::{DnsLimits, DnsName, DnsQueryType, DnsRecordValue, ValidatedDnsResponse};
use super::super::{
    DNS_CLASS_IN, DNS_FLAG_AUTHENTICATED_DATA, DNS_FLAG_AUTHORITATIVE, DNS_FLAG_CHECKING_DISABLED,
    DNS_FLAG_RECURSION_AVAILABLE, DNS_FLAG_RECURSION_DESIRED, DNS_FLAG_RESPONSE,
    DNS_FLAG_TRUNCATED, DNS_HEADER_BYTES, DNS_OPCODE_MASK, DNS_RCODE_MASK, DNS_RESERVED_MASK,
};
use super::name::{canonical_query_name, decode_name};
use super::relevance::{RelevantRecords, filter_relevant_records};

use primitives::read_u16;
use records::decode_records;

mod primitives;
mod records;

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
