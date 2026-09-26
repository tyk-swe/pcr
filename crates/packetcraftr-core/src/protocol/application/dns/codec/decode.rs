// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::super::{DecodeLimits, Dns, Error, Name, Question};
use bytes::Bytes;
pub use primitives::read_u16;
mod primitives;
mod records;

pub(super) fn advance(offset: usize, delta: usize, field: &'static str) -> Result<usize, Error> {
    offset.checked_add(delta).ok_or(Error::TruncatedField {
        field,
        offset,
        needed: usize::MAX,
    })
}

/// Decompresses one bounded, lossless name and returns its wire resume offset.
pub fn decode_name(
    message: &Bytes,
    offset: usize,
    limits: DecodeLimits,
) -> Result<(Name, usize), Error> {
    limits.validate()?;
    let expanded = super::name::decompress(message, offset, limits.max_name_pointers)?;
    Ok((
        Name {
            labels: expanded.labels,
        },
        expanded.resume,
    ))
}

pub(super) fn decode(wire: Bytes, limits: DecodeLimits) -> Result<Dns, Error> {
    limits.validate()?;
    let message = wire.as_ref();
    let maximum = limits.max_message_bytes;
    if message.len() > maximum {
        return Err(Error::MessageTooLarge {
            actual: message.len(),
            maximum,
        });
    }
    if message.len() < 12 {
        return Err(Error::MessageTooShort {
            actual: message.len(),
            minimum: 12,
        });
    }
    let flags = read_u16(message, 2, "flags")?;
    let question_count = read_u16(message, 4, "question count")?;
    let answer_count = read_u16(message, 6, "answer count")?;
    let authority_count = read_u16(message, 8, "authority count")?;
    let additional_count = read_u16(message, 10, "additional count")?;
    if question_count > 64 {
        return Err(Error::QuestionLimit {
            actual: usize::from(question_count),
            limit: 64,
        });
    }
    let count =
        usize::from(answer_count) + usize::from(authority_count) + usize::from(additional_count);
    let limit = limits.max_records;
    if count > limit {
        return Err(Error::RecordLimit {
            actual: count,
            limit,
        });
    }
    let mut questions = Vec::with_capacity(usize::from(question_count));
    let mut offset = 12;
    for _ in 0..question_count {
        let (name, next) = decode_name(&wire, offset, limits)?;
        questions.push(Question {
            name,
            query_type: read_u16(message, next, "question type")?,
            class: read_u16(
                message,
                advance(next, 2, "question class")?,
                "question class",
            )?,
        });
        offset = advance(next, 4, "question")?;
    }
    let (answers, next) =
        records::decode_records(&wire, offset, usize::from(answer_count), limits)?;
    let (authorities, next) =
        records::decode_records(&wire, next, usize::from(authority_count), limits)?;
    let (additionals, next) =
        records::decode_records(&wire, next, usize::from(additional_count), limits)?;
    if next != message.len() {
        return Err(Error::TrailingBytes {
            remaining: message.len() - next,
        });
    }
    // Offline inspection retains OPT records exactly where they occurred. Live
    // response validation applies section, uniqueness, owner and version rules.
    Ok(Dns {
        id: read_u16(message, 0, "transaction ID")?,
        response: flags & 0x8000 != 0,
        opcode: ((flags >> 11) & 15) as u8,
        authoritative_answer: flags & 0x0400 != 0,
        truncated: flags & 0x0200 != 0,
        recursion_desired: flags & 0x0100 != 0,
        recursion_available: flags & 0x0080 != 0,
        authenticated_data: flags & 0x0020 != 0,
        checking_disabled: flags & 0x0010 != 0,
        rcode: (flags & 15) as u8,
        question_count: crate::field::WireValue::Exact(question_count),
        answer_count: crate::field::WireValue::Exact(answer_count),
        authority_count: crate::field::WireValue::Exact(authority_count),
        additional_count: crate::field::WireValue::Exact(additional_count),
        questions,
        reserved: flags & 0x0040 != 0,
        answers,
        authorities,
        additionals,
        wire,
    })
}
