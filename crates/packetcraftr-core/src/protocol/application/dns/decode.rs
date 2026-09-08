// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::{DecodeError, DecodeLimits, Dns, Name};
use bytes::Bytes;
use primitives::read_u16;
mod primitives;
mod records;

pub(super) fn advance(
    offset: usize,
    delta: usize,
    field: &'static str,
) -> Result<usize, DecodeError> {
    offset
        .checked_add(delta)
        .ok_or(DecodeError::TruncatedField {
            field,
            offset,
            needed: usize::MAX,
        })
}

/// Decompresses one bounded, lossless name and returns its wire resume offset.
pub fn decode_name(
    message: &[u8],
    offset: usize,
    limits: DecodeLimits,
) -> Result<(Name, usize), DecodeError> {
    let expanded = super::name::decompress(message, offset, limits.max_name_pointers.min(128))?;
    Ok((
        Name {
            labels: expanded.labels,
        },
        expanded.resume,
    ))
}

pub(super) fn decode(wire: Bytes, limits: DecodeLimits) -> Result<Dns, DecodeError> {
    let message = wire.as_ref();
    let maximum = limits.max_message_bytes.min(u16::MAX as usize);
    if message.len() > maximum {
        return Err(DecodeError::MessageTooLarge {
            actual: message.len(),
            maximum,
        });
    }
    if message.len() < 12 {
        return Err(DecodeError::MessageTooShort {
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
        return Err(DecodeError::QuestionLimit {
            actual: usize::from(question_count),
            limit: 64,
        });
    }
    let count =
        usize::from(answer_count) + usize::from(authority_count) + usize::from(additional_count);
    let limit = limits.max_records.min(4096);
    if count > limit {
        return Err(DecodeError::RecordLimit {
            actual: count,
            limit,
        });
    }
    let mut qnames = Vec::with_capacity(usize::from(question_count));
    let mut qtypes = Vec::with_capacity(usize::from(question_count));
    let mut qclasses = Vec::with_capacity(usize::from(question_count));
    let mut offset = 12;
    for _ in 0..question_count {
        let (name, next) = decode_name(message, offset, limits)?;
        // Preserve the existing offline question presentation of ASCII spaces.
        qnames.push(name.to_string().replace("\\032", " "));
        qtypes.push(read_u16(message, next, "question type")?);
        qclasses.push(read_u16(
            message,
            advance(next, 2, "question class")?,
            "question class",
        )?);
        offset = advance(next, 4, "question")?;
    }
    let limits = DecodeLimits {
        max_txt_strings: limits.max_txt_strings.min(4096),
        max_txt_bytes: limits.max_txt_bytes.min(u16::MAX as usize),
        ..limits
    };
    let (answers, next) =
        records::decode_records(message, offset, usize::from(answer_count), limits)?;
    let (authorities, next) =
        records::decode_records(message, next, usize::from(authority_count), limits)?;
    let (additionals, next) =
        records::decode_records(message, next, usize::from(additional_count), limits)?;
    if next != message.len() {
        return Err(DecodeError::TrailingBytes {
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
        question_count,
        answer_count,
        authority_count,
        additional_count,
        qnames,
        qtypes,
        qclasses,
        answers,
        authorities,
        additionals,
        wire,
    })
}
