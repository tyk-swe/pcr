// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::super::describe;
use super::{Subject, parse_subject, record_requirements};
use crate::field::FieldKind;
use crate::filter::ast::{Measure, Predicate};
use crate::filter::error::Error;
use crate::filter::eval;
use crate::filter::lexer::{Spanned, Token};
use crate::filter::literal::{self, Literal};
use crate::filter::path::{self, FieldRef, FieldSource, FrameField};
use crate::filter::requirements::Requirements;
use crate::registry::Registry;

/// `len` or `count` directly followed by `(`; without the parenthesis they stay ordinary words.
pub(super) fn measure_call(tokens: &[Spanned], start: usize) -> Option<Measure> {
    let Some(Spanned {
        token: Token::Word(word),
        offset,
    }) = tokens.get(start)
    else {
        return None;
    };
    // the word is the source text, so the parenthesis must begin where it ends
    if !matches!(
        tokens.get(start.saturating_add(1)),
        Some(Spanned {
            token: Token::LeftParen,
            offset: open,
        }) if *open == offset.saturating_add(word.len())
    ) {
        return None;
    }
    if word.eq_ignore_ascii_case("len") {
        Some(Measure::Len)
    } else if word.eq_ignore_ascii_case("count") {
        Some(Measure::Count)
    } else {
        None
    }
}

/// `len(FIELD) OP N` or `count(FIELD) OP N`; `start` addresses the function name.
pub(super) fn parse_measure(
    tokens: &[Spanned],
    start: usize,
    measure: Measure,
    registry: &Registry,
    requirements: &mut Requirements,
) -> Result<(Predicate, usize), Error> {
    let name = match measure {
        Measure::Len => "len",
        Measure::Count => "count",
    };
    let syntax = |offset: usize, message: String| Error::Syntax { offset, message };
    // measure_call saw both the name and the `(`
    let open = &tokens[start.saturating_add(1)];
    let inner = start.saturating_add(2);
    if !matches!(
        tokens.get(inner),
        Some(Spanned {
            token: Token::Word(_),
            ..
        })
    ) {
        return Err(syntax(open.offset, format!("`{name}(` needs a field path")));
    }
    let (mut field, mut index) = match parse_subject(tokens, inner, registry)? {
        Subject::Field { field, index } => (field, index),
        Subject::Predicate(..) => {
            return Err(syntax(
                tokens[inner].offset,
                format!("`{name}(` takes a field, not a layer"),
            ));
        }
    };
    if let Some(Spanned {
        token: Token::Slice(contents),
        offset,
    }) = tokens.get(index)
    {
        path::attach_slice(&mut field, contents, *offset)?;
        index = index.saturating_add(1);
    }
    if !matches!(
        tokens.get(index),
        Some(Spanned {
            token: Token::RightParen,
            ..
        })
    ) {
        return Err(syntax(
            tokens.get(index).map_or(open.offset, |token| token.offset),
            format!("expected `)` to close `{name}(`"),
        ));
    }
    check_measurable(&field, measure, open.offset)?;
    record_requirements(&field, requirements);
    let compare = index.saturating_add(1);
    let Some(Spanned {
        token: Token::Compare(operator),
        offset: operator_offset,
    }) = tokens.get(compare)
    else {
        return Err(syntax(
            tokens
                .get(compare)
                .map_or(open.offset, |token| token.offset),
            format!(
                "`{name}(..)` must be compared to a number, as in `{name}({}) > 1`",
                field.path
            ),
        ));
    };
    let value = compare.saturating_add(1);
    let amount = match tokens.get(value) {
        Some(Spanned {
            token: Token::Word(word),
            ..
        }) => match literal::parse(word) {
            Some(Literal::Unsigned(amount)) => amount,
            _ => {
                return Err(syntax(
                    tokens[value].offset,
                    format!("`{name}(..)` is compared to an unsigned number, found `{word}`"),
                ));
            }
        },
        other => {
            return Err(syntax(
                other.map_or(*operator_offset, |token| token.offset),
                format!(
                    "`{name}(..)` is compared to an unsigned number, found {}",
                    other.map_or_else(
                        || "the end of the filter".to_owned(),
                        |token| describe(&token.token)
                    )
                ),
            ));
        }
    };
    Ok((
        Predicate::Measure {
            field,
            measure,
            operator: *operator,
            value: amount,
        },
        value.saturating_add(1),
    ))
}

/// `len` needs bytes, text, an address, or a list of them; `count` needs a whole list.
fn check_measurable(field: &FieldRef, measure: Measure, offset: usize) -> Result<(), Error> {
    if field.specs.is_empty() {
        return Ok(());
    }
    // Each protocol id is text, so `len` would measure ids, not layers.
    if measure == Measure::Len && matches!(field.source, FieldSource::Frame(FrameField::Protocols))
    {
        return Err(Error::Syntax {
            offset,
            message: format!(
                "`len(` would measure each protocol name, not the layers; use `count({0})` or `frame.layer_count`",
                field.path
            ),
        });
    }
    let measurable = match measure {
        Measure::Len => field.specs.iter().any(|spec| {
            eval::byte_addressable(spec.kind) || (spec.kind == FieldKind::List && !spec.structured)
        }),
        Measure::Count => {
            field.specs.iter().any(|spec| spec.kind == FieldKind::List)
                && field.slice.is_none()
                && !field.reads_list_elements()
        }
    };
    if measurable {
        return Ok(());
    }
    let (name, needs) = match measure {
        Measure::Len => ("len", "bytes, text, an address, or a list of them"),
        Measure::Count => ("count", "a whole list"),
    };
    Err(Error::Syntax {
        offset,
        message: format!(
            "`{name}(` needs a field holding {needs}, but `{}` does not",
            field.path
        ),
    })
}
