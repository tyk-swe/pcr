// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Ordered DNS response validation and decoding orchestration.

use super::name::{canonical_query_name, decode_name};
use super::relevance::{RelevantRecords, filter_relevant_records};
use crate::dns::error::WireError;
use crate::dns::model::{
    Edns, MessageLimits, Name, QueryType, Record, RecordValue, ResponseMetadata, ValidatedResponse,
};
use crate::dns::{
    CLASS_IN, FLAG_AUTHENTICATED_DATA, FLAG_AUTHORITATIVE, FLAG_CHECKING_DISABLED,
    FLAG_RECURSION_AVAILABLE, FLAG_RECURSION_DESIRED, FLAG_RESPONSE, FLAG_TRUNCATED, HEADER_BYTES,
    OPCODE_MASK, RCODE_MASK, RESERVED_MASK,
};

use primitives::read_u16;
use records::decode_records;

mod primitives;
mod records;

/// Decodes the length prefix of a single DNS-over-TCP frame, then applies the
/// same transaction, question, bounds, and relevance validation as UDP.
pub fn decode_tcp_frame(
    frame: &[u8],
    query_name: &str,
    query_type: QueryType,
    transaction_id: u16,
    limits: MessageLimits,
) -> Result<ValidatedResponse, WireError> {
    let prefix = frame.first_chunk::<2>().ok_or(WireError::MessageTooShort {
        actual: frame.len(),
        minimum: 2,
    })?;
    let declared = usize::from(u16::from_be_bytes(*prefix));
    if declared == 0 {
        return Err(WireError::TcpFrameZeroLength);
    }
    if declared > limits.max_message_bytes {
        return Err(WireError::MessageTooLarge {
            actual: declared,
            maximum: limits.max_message_bytes,
        });
    }
    let payload = frame.get(2..).ok_or(WireError::MessageTooShort {
        actual: frame.len(),
        minimum: 2,
    })?;
    if declared != payload.len() {
        return Err(WireError::TcpFrameLength {
            declared,
            actual: payload.len(),
        });
    }
    let response = decode_response(payload, query_name, query_type, transaction_id, limits)?;
    if response.metadata.truncated {
        return Err(WireError::TcpResponseTruncated);
    }
    Ok(response)
}

/// Decodes a DNS response, accepting relevant records and retaining a bounded
/// audit of other declared records.
pub fn decode_response(
    message: &[u8],
    query_name: &str,
    query_type: QueryType,
    transaction_id: u16,
    limits: MessageLimits,
) -> Result<ValidatedResponse, WireError> {
    let query_name = canonical_query_name(query_name)?;
    let expected_name = Name::from_canonical_ascii(&query_name);
    validate_message_bounds(message, limits)?;
    let header = decode_header(message, transaction_id)?;
    let offset = decode_question(message, &query_name, &expected_name, query_type, limits)?;

    if header.flags & FLAG_TRUNCATED != 0 {
        return Ok(truncated_response(header.flags));
    }

    validate_record_count(&header, limits)?;
    let sections = decode_sections(message, offset, &header, limits)?;
    let response_code = (sections
        .edns
        .as_ref()
        .map_or(0, |edns| u16::from(edns.extended_response_code))
        << 4)
        | (header.flags & RCODE_MASK);
    let RelevantRecords {
        answers,
        authorities,
        additionals,
        rejected_records,
        rejected_record_count,
    } = filter_relevant_records(
        &expected_name,
        query_type,
        sections.answers,
        sections.authorities,
        sections.additionals,
        limits.max_rejected_records,
    );
    Ok(ValidatedResponse {
        metadata: ResponseMetadata {
            response_code,
            edns: sections.edns,
            authoritative: header.flags & FLAG_AUTHORITATIVE != 0,
            truncated: false,
            recursion_desired: header.flags & FLAG_RECURSION_DESIRED != 0,
            recursion_available: header.flags & FLAG_RECURSION_AVAILABLE != 0,
            authenticated_data: header.flags & FLAG_AUTHENTICATED_DATA != 0,
            checking_disabled: header.flags & FLAG_CHECKING_DISABLED != 0,
            rejected_record_count,
        },
        answers,
        authorities,
        additionals,
        rejected_records,
    })
}

struct ResponseHeader {
    flags: u16,
    answer_count: usize,
    authority_count: usize,
    additional_count: usize,
}

struct ResponseSections {
    answers: Vec<Record>,
    authorities: Vec<Record>,
    additionals: Vec<Record>,
    edns: Option<Edns>,
}

/// Advances a message offset, reporting truncation instead of wrapping.
fn advance(offset: usize, delta: usize, field: &'static str) -> Result<usize, WireError> {
    offset
        .checked_add(delta)
        .ok_or(WireError::TruncatedField { field, offset })
}

fn validate_message_bounds(message: &[u8], limits: MessageLimits) -> Result<(), WireError> {
    if message.len() < HEADER_BYTES {
        return Err(WireError::MessageTooShort {
            actual: message.len(),
            minimum: HEADER_BYTES,
        });
    }
    if message.len() > limits.max_message_bytes {
        return Err(WireError::MessageTooLarge {
            actual: message.len(),
            maximum: limits.max_message_bytes,
        });
    }
    Ok(())
}

fn decode_header(message: &[u8], transaction_id: u16) -> Result<ResponseHeader, WireError> {
    let actual_id = read_u16(message, 0, "transaction ID")?;
    let flags = read_u16(message, 2, "flags")?;
    if flags & FLAG_RESPONSE == 0 {
        return Err(WireError::NotResponse);
    }
    let opcode = u8::try_from((flags & OPCODE_MASK) >> 11).unwrap_or_default();
    if opcode != 0 {
        return Err(WireError::UnsupportedOpcode { opcode });
    }
    if flags & RESERVED_MASK != 0 {
        return Err(WireError::ReservedHeaderBits);
    }
    if actual_id != transaction_id {
        return Err(WireError::TransactionIdMismatch {
            expected: transaction_id,
            actual: actual_id,
        });
    }
    let question_count = read_u16(message, 4, "question count")?;
    if question_count != 1 {
        return Err(WireError::QuestionCount {
            actual: question_count,
        });
    }
    Ok(ResponseHeader {
        flags,
        answer_count: usize::from(read_u16(message, 6, "answer count")?),
        authority_count: usize::from(read_u16(message, 8, "authority count")?),
        additional_count: usize::from(read_u16(message, 10, "additional count")?),
    })
}

fn decode_question(
    message: &[u8],
    query_name: &str,
    expected_name: &Name,
    query_type: QueryType,
    limits: MessageLimits,
) -> Result<usize, WireError> {
    let (actual_name, mut offset) = decode_name(message, HEADER_BYTES, limits)?;
    if actual_name != *expected_name {
        return Err(WireError::QuestionNameMismatch {
            expected: query_name.to_owned(),
            actual: actual_name.to_string(),
        });
    }
    let actual_type = read_u16(message, offset, "question type")?;
    offset = advance(offset, 2, "question class")?;
    if actual_type != query_type.code() {
        return Err(WireError::QuestionTypeMismatch {
            expected: query_type.code(),
            actual: actual_type,
        });
    }
    let actual_class = read_u16(message, offset, "question class")?;
    offset = advance(offset, 2, "answer section")?;
    if actual_class != CLASS_IN {
        return Err(WireError::QuestionClassMismatch {
            actual: actual_class,
        });
    }
    Ok(offset)
}

fn truncated_response(flags: u16) -> ValidatedResponse {
    // A UDP truncation may end at any byte after the complete question.
    // Do not decode or present possibly partial records as accepted facts.
    ValidatedResponse {
        metadata: ResponseMetadata {
            response_code: flags & RCODE_MASK,
            edns: None,
            authoritative: flags & FLAG_AUTHORITATIVE != 0,
            truncated: true,
            recursion_desired: flags & FLAG_RECURSION_DESIRED != 0,
            recursion_available: flags & FLAG_RECURSION_AVAILABLE != 0,
            authenticated_data: flags & FLAG_AUTHENTICATED_DATA != 0,
            checking_disabled: flags & FLAG_CHECKING_DISABLED != 0,
            rejected_record_count: 0,
        },
        answers: Vec::new(),
        authorities: Vec::new(),
        additionals: Vec::new(),
        rejected_records: Vec::new(),
    }
}

fn validate_record_count(header: &ResponseHeader, limits: MessageLimits) -> Result<(), WireError> {
    let record_count = header
        .answer_count
        .checked_add(header.authority_count)
        .and_then(|count| count.checked_add(header.additional_count))
        .ok_or(WireError::RecordLimit {
            actual: usize::MAX,
            limit: limits.max_records,
        })?;
    if record_count > limits.max_records {
        return Err(WireError::RecordLimit {
            actual: record_count,
            limit: limits.max_records,
        });
    }
    Ok(())
}

fn decode_sections(
    message: &[u8],
    offset: usize,
    header: &ResponseHeader,
    limits: MessageLimits,
) -> Result<ResponseSections, WireError> {
    let (answers, next) = decode_records(message, offset, header.answer_count, limits)?;
    let (authorities, next) = decode_records(message, next, header.authority_count, limits)?;
    let (additionals, next) = decode_records(message, next, header.additional_count, limits)?;
    if next != message.len() {
        return Err(WireError::TrailingBytes {
            remaining: message.len().saturating_sub(next),
        });
    }
    if answers
        .iter()
        .chain(&authorities)
        .any(|record| matches!(record.value, RecordValue::Opt(_)))
    {
        return Err(WireError::InvalidEdns {
            message: "OPT pseudo-record must appear only in the additional section".to_owned(),
        });
    }
    let (edns, additionals) = extract_edns(additionals)?;
    Ok(ResponseSections {
        answers,
        authorities,
        additionals,
        edns,
    })
}

fn extract_edns(additionals: Vec<Record>) -> Result<(Option<Edns>, Vec<Record>), WireError> {
    let mut edns = None;
    let mut non_opt_additionals = Vec::with_capacity(additionals.len());
    for record in additionals {
        match &record.value {
            RecordValue::Opt(value) => {
                if !record.owner.is_root() {
                    return Err(WireError::InvalidEdns {
                        message: "OPT owner name must be the root".to_owned(),
                    });
                }
                if edns.replace(value.clone()).is_some() {
                    return Err(WireError::DuplicateEdns);
                }
            }
            _ => non_opt_additionals.push(record),
        }
    }
    Ok((edns, non_opt_additionals))
}
