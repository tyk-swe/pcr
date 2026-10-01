// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use bytes::Bytes;

use super::super::describe;
use crate::field::FieldKind;
use crate::filter::error::Error;
use crate::filter::lexer::{Spanned, Token};
use crate::filter::literal::{self, Literal};
use crate::filter::path::FieldRef;

#[cfg(test)]
mod tests;

/// A decimal or `0x` hexadecimal number; `fallback` locates the error when the filter ends first.
pub(super) fn unsigned_operand(
    field: &FieldRef,
    tokens: &[Spanned],
    index: usize,
    fallback: usize,
) -> Result<u64, Error> {
    let refusal = |offset: usize, found: String| Error::MaskOperand {
        offset,
        path: field.path.clone(),
        found,
    };
    let Some(Spanned { token, offset }) = tokens.get(index) else {
        return Err(refusal(fallback, "the end of the filter".to_owned()));
    };
    match token {
        Token::Word(word) => match literal::parse(word) {
            Some(Literal::Unsigned(value)) => Ok(value),
            _ => Err(refusal(*offset, describe(token))),
        },
        other => Err(refusal(*offset, describe(other))),
    }
}

pub(super) fn parse_literal(
    field: &FieldRef,
    tokens: &[Spanned],
    index: usize,
    operator_offset: usize,
) -> Result<(Literal, usize), Error> {
    let Some(Spanned { token, offset }) = tokens.get(index) else {
        return Err(Error::Syntax {
            offset: operator_offset,
            message: "expected a value".to_owned(),
        });
    };
    let value = match token {
        Token::Text(text) => Literal::Text(text.clone()),
        Token::ByteString(bytes) => Literal::Bytes(Bytes::copy_from_slice(bytes)),
        Token::Word(word) => match range_or_literal(field, word, *offset)? {
            Some(value) => value,
            None if field.is_byte_run() && literal::is_malformed_byte_word(word) => {
                return Err(Error::UnquotedByteWord {
                    offset: *offset,
                    path: field.path.clone(),
                    literal: word.clone(),
                });
            }
            None => Literal::Text(word.clone()),
        },
        other => {
            return Err(Error::Syntax {
                offset: *offset,
                message: format!("expected a value, found {}", describe(other)),
            });
        }
    };
    Ok((value, index.saturating_add(1)))
}

/// Only fields that can hold a number or an address read `A..B` as a range; elsewhere it stays text.
fn range_or_literal(field: &FieldRef, word: &str, offset: usize) -> Result<Option<Literal>, Error> {
    let ranged = field.specs.is_empty()
        || field.specs.iter().any(|spec| {
            matches!(
                spec.kind,
                FieldKind::Unsigned
                    | FieldKind::Signed
                    | FieldKind::Ipv4
                    | FieldKind::Ipv6
                    | FieldKind::List
            )
        });
    let range = if ranged {
        literal::parse_range(word)
    } else {
        None
    };
    match range {
        Some(Ok(value)) => Ok(Some(value)),
        Some(Err(reason)) => Err(Error::InvalidRange {
            offset,
            path: field.path.clone(),
            literal: word.to_owned(),
            reason,
        }),
        None => Ok(literal::parse(word)),
    }
}

pub(super) fn check_literal(field: &FieldRef, value: &Literal, offset: usize) -> Result<(), Error> {
    if field.specs.is_empty() {
        return Ok(());
    }
    if field
        .specs
        .iter()
        .any(|spec| literal::compatible(*spec, value))
    {
        return Ok(());
    }
    Err(incompatible(field, value, offset))
}

/// Without this, a mistyped `contains` compiles and then filters out every packet.
pub(super) fn check_searchable(
    field: &FieldRef,
    needle: &Literal,
    offset: usize,
) -> Result<(), Error> {
    if field.specs.is_empty() {
        return Ok(());
    }
    if field.specs.iter().any(|spec| literal::searchable(*spec)) {
        return Ok(());
    }
    Err(incompatible(field, needle, offset))
}

pub(super) fn incompatible(field: &FieldRef, value: &Literal, offset: usize) -> Error {
    Error::IncompatibleLiteral {
        offset,
        path: field.path.clone(),
        kind: literal::kind_name(
            field
                .specs
                .first()
                .map_or(FieldKind::Bytes, |spec| spec.kind),
        ),
        literal: value.to_string(),
    }
}
