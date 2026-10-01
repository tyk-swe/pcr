// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::super::{Dns, Error, Limits, MAX_QUESTIONS, Name, Question};
use super::HEADER_LEN;
use bytes::Bytes;
use primitives::read_u16;
mod primitives;
mod records;

/// Decodes the possibly-compressed name that starts at `offset` in `message`,
/// returning it with the offset where the reader continues.
///
/// ```
/// use bytes::Bytes;
/// use packetcraftr_core::protocol::application::dns::{Limits, Error, decode_name};
///
/// // "a" then a pointer back to the root label at offset 0.
/// let message = Bytes::from_static(&[0x00, 0x01, b'a', 0xc0, 0x00]);
/// let (name, resume) = decode_name(&message, 1, Limits::default()).expect("bounded name");
/// assert_eq!(name.labels(), [Bytes::from_static(b"a")]);
/// assert_eq!(resume, 5);
///
/// // A pointer that does not move backward cannot terminate.
/// assert!(matches!(
///     decode_name(&Bytes::from_static(&[0xc0, 0x00]), 0, Limits::default()),
///     Err(Error::SelfPointer { offset: 0 }),
/// ));
/// ```
pub fn decode_name(message: &Bytes, offset: usize, limits: Limits) -> Result<(Name, usize), Error> {
    limits.validate()?;
    let expanded = super::name::decompress(message, offset, limits.max_name_pointers)?;
    Ok((
        Name {
            labels: expanded.labels,
        },
        expanded.resume,
    ))
}

/// `mdns` says the transport identified the message as multicast DNS, so
/// record classes may carry the RFC 6762 cache-flush bit.
pub(super) fn decode(wire: Bytes, limits: Limits, mdns: bool) -> Result<Dns, Error> {
    limits.validate()?;
    let message = wire.as_ref();
    let maximum = limits.max_message_bytes;
    if message.len() > maximum {
        return Err(Error::MessageTooLarge {
            actual: message.len(),
            maximum,
        });
    }
    if message.len() < HEADER_LEN {
        return Err(Error::MessageTooShort {
            actual: message.len(),
            minimum: HEADER_LEN,
        });
    }
    let flags = read_u16(message, 2, "flags")?;
    let question_count = read_u16(message, 4, "question count")?;
    let answer_count = read_u16(message, 6, "answer count")?;
    let authority_count = read_u16(message, 8, "authority count")?;
    let additional_count = read_u16(message, 10, "additional count")?;
    if usize::from(question_count) > MAX_QUESTIONS {
        return Err(Error::QuestionLimit {
            actual: usize::from(question_count),
            limit: MAX_QUESTIONS,
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
    let mut offset = HEADER_LEN;
    for _ in 0..question_count {
        let (name, next) = decode_name(&wire, offset, limits)?;
        questions.push(Question {
            name,
            query_type: read_u16(message, next, "question type")?,
            class: read_u16(message, next + 2, "question class")?,
        });
        offset = next + 4;
    }
    let (answers, next) =
        records::decode_records(&wire, offset, usize::from(answer_count), limits, mdns)?;
    let (authorities, next) =
        records::decode_records(&wire, next, usize::from(authority_count), limits, mdns)?;
    let (additionals, next) =
        records::decode_records(&wire, next, usize::from(additional_count), limits, mdns)?;
    if next != message.len() {
        return Err(Error::TrailingBytes {
            remaining: message.len() - next,
        });
    }
    // Offline inspection retains OPT records exactly where they occurred.
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
        mdns,
    })
}
