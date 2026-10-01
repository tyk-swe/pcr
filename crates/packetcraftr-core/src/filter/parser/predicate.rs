// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::field::FieldKind;
use crate::filter::ast::Predicate;
use crate::filter::comparison::Needle;
use crate::filter::error::Error;
use crate::filter::lexer::{CompareOperator, Spanned, Token};
use crate::filter::limits::Limits;
use crate::filter::literal;
use crate::filter::path::{self, FieldRef, FieldSource, FrameField, Resolved};
use crate::filter::requirements::Requirements;
use crate::registry::Registry;

mod measure;
mod operand;

use operand::{check_literal, check_searchable, incompatible, parse_literal, unsigned_operand};

pub(super) fn parse(
    tokens: &[Spanned],
    start: usize,
    registry: &Registry,
    limits: &Limits,
    requirements: &mut Requirements,
) -> Result<(Predicate, usize), Error> {
    if let Some(measure) = measure::measure_call(tokens, start) {
        return measure::parse_measure(tokens, start, measure, registry, requirements);
    }
    let (mut field, mut index) = match parse_subject(tokens, start, registry)? {
        Subject::Field { field, index } => (field, index),
        Subject::Predicate(predicate, index) => return Ok((predicate, index)),
    };
    if let Some(Spanned {
        token: Token::Slice(contents),
        offset,
    }) = tokens.get(index)
    {
        path::attach_slice(&mut field, contents, *offset)?;
        index = index.saturating_add(1);
    }
    record_requirements(&field, requirements);
    parse_field_predicate(tokens, index, field, limits)
}

enum Subject {
    Field { field: FieldRef, index: usize },
    Predicate(Predicate, usize),
}

fn parse_subject(tokens: &[Spanned], start: usize, registry: &Registry) -> Result<Subject, Error> {
    // start is the index of the Word token consume_operand already read
    let Spanned { token, offset } = &tokens[start];
    let offset = *offset;
    let Token::Word(word) = token else {
        return Err(Error::Syntax {
            offset,
            message: "expected a field path".to_owned(),
        });
    };
    let mut index = start.saturating_add(1);
    let mut combined = word.clone();
    while let Some(Spanned {
        token: Token::Slice(contents),
        ..
    }) = tokens.get(index)
    {
        let selector = matches!(contents.as_str(), "*" | "-1");
        if !selector && (contents.is_empty() || !contents.bytes().all(|byte| byte.is_ascii_digit()))
        {
            break;
        }
        let mut candidate = format!("{combined}[{contents}]");
        let mut next = index + 1;
        if let Some(Spanned {
            token: Token::Word(tail),
            ..
        }) = tokens.get(next)
            && tail.starts_with('.')
        {
            candidate.push_str(tail);
            next += 1;
        }
        match path::resolve(&candidate, registry, offset) {
            Ok(Resolved::Field(_)) => {}
            // A selector is never a byte slice, so a path it cannot select from is an error.
            Err(error) if selector || next > index + 1 => return Err(error),
            _ => break,
        }
        combined = candidate;
        index = next;
    }
    let resolved = path::resolve(&combined, registry, offset)?;

    let field = match resolved {
        Resolved::Layer {
            protocol,
            occurrence,
        } => {
            if let Some(Spanned {
                token: Token::Slice(_),
                offset: slice_offset,
            }) = tokens.get(index)
            {
                return Err(Error::UnsliceableField {
                    offset: *slice_offset,
                    path: word.clone(),
                });
            }
            if let Some(Spanned {
                token:
                    Token::Compare(_)
                    | Token::In
                    | Token::Contains
                    | Token::TextMatch(_)
                    | Token::Ampersand,
                offset: operator_offset,
            }) = tokens.get(index)
            {
                return Err(Error::Syntax {
                    offset: *operator_offset,
                    message: format!("`{word}` names a layer, not a field, so it has no value"),
                });
            }
            return Ok(Subject::Predicate(
                Predicate::LayerPresent {
                    protocol,
                    occurrence,
                },
                index,
            ));
        }
        Resolved::Field(field) => field,
    };
    Ok(Subject::Field { field, index })
}

fn record_requirements(field: &FieldRef, requirements: &mut Requirements) {
    if let FieldSource::Stream(transport) = &field.source {
        requirements.require_stream(*transport);
    }
    if matches!(
        field.source,
        FieldSource::Frame(FrameField::TimeEpoch | FrameField::TimeNanoseconds)
    ) {
        requirements.timestamp = true;
    }
}

fn parse_field_predicate(
    tokens: &[Spanned],
    index: usize,
    field: FieldRef,
    limits: &Limits,
) -> Result<(Predicate, usize), Error> {
    match tokens.get(index) {
        Some(Spanned {
            token: Token::Compare(operator),
            offset: operator_offset,
        }) => {
            let (value, next) =
                parse_literal(&field, tokens, index.saturating_add(1), *operator_offset)?;
            check_literal(&field, &value, *operator_offset)?;
            if value.is_prefix()
                && !matches!(operator, CompareOperator::Equal | CompareOperator::NotEqual)
            {
                return Err(Error::OrderedPrefixComparison {
                    offset: *operator_offset,
                    path: field.path,
                    literal: value.to_string(),
                });
            }
            if value.is_range()
                && !matches!(operator, CompareOperator::Equal | CompareOperator::NotEqual)
            {
                return Err(Error::OrderedRangeComparison {
                    offset: *operator_offset,
                    path: field.path,
                    literal: value.to_string(),
                });
            }
            Ok((
                Predicate::Compare {
                    field,
                    operator: *operator,
                    value,
                },
                next,
            ))
        }
        Some(Spanned {
            token: Token::Contains,
            offset: operator_offset,
        }) => {
            let (needle, next) =
                parse_literal(&field, tokens, index.saturating_add(1), *operator_offset)?;
            check_searchable(&field, &needle, *operator_offset)?;
            let needle = Needle::new(needle)
                .map_err(|literal| incompatible(&field, &literal, *operator_offset))?;
            Ok((Predicate::Contains { field, needle }, next))
        }
        Some(Spanned {
            token: Token::TextMatch(mode),
            offset: operator_offset,
        }) => {
            let (needle, next) =
                parse_literal(&field, tokens, index.saturating_add(1), *operator_offset)?;
            check_searchable(&field, &needle, *operator_offset)?;
            let needle = Needle::for_mode(needle, *mode)
                .map_err(|literal| incompatible(&field, &literal, *operator_offset))?;
            let mode = *mode;
            Ok((
                Predicate::TextMatch {
                    field,
                    needle,
                    mode,
                },
                next,
            ))
        }
        Some(Spanned {
            token: Token::Ampersand,
            offset: operator_offset,
        }) => parse_masked(tokens, index, field, *operator_offset),
        Some(Spanned {
            token: Token::In,
            offset: operator_offset,
        }) => parse_membership(
            tokens,
            index.saturating_add(1),
            field,
            limits,
            *operator_offset,
        ),
        _ => {
            let flag = field.is_flag();
            Ok((Predicate::Bare { field, flag }, index))
        }
    }
}

/// `index` addresses the `&`. The bare form `field & mask` means the masked value is nonzero.
fn parse_masked(
    tokens: &[Spanned],
    index: usize,
    field: FieldRef,
    operator_offset: usize,
) -> Result<(Predicate, usize), Error> {
    if !field.specs.is_empty()
        && !field
            .specs
            .iter()
            .all(|spec| spec.kind == FieldKind::Unsigned)
    {
        return Err(Error::MaskedField {
            offset: operator_offset,
            path: field.path,
            kind: literal::kind_name(
                field
                    .specs
                    .iter()
                    .map(|spec| spec.kind)
                    .find(|kind| *kind != FieldKind::Unsigned)
                    .unwrap_or(FieldKind::Unsigned),
            ),
        });
    }
    let mask_index = index.saturating_add(1);
    let mask = unsigned_operand(&field, tokens, mask_index, operator_offset)?;
    let after = mask_index.saturating_add(1);
    let Some(Spanned {
        token: Token::Compare(operator),
        offset: compare_offset,
    }) = tokens.get(after)
    else {
        return Ok((
            Predicate::Masked {
                field,
                mask,
                operator: CompareOperator::NotEqual,
                value: 0,
            },
            after,
        ));
    };
    let value_index = after.saturating_add(1);
    let value = unsigned_operand(&field, tokens, value_index, *compare_offset)?;
    Ok((
        Predicate::Masked {
            field,
            mask,
            operator: *operator,
            value,
        },
        value_index.saturating_add(1),
    ))
}

fn parse_membership(
    tokens: &[Spanned],
    start: usize,
    field: FieldRef,
    limits: &Limits,
    offset: usize,
) -> Result<(Predicate, usize), Error> {
    let Some(first) = tokens.get(start) else {
        return Err(Error::Syntax {
            offset,
            message: "`in` needs a value or a `{ .. }` set".to_owned(),
        });
    };
    if !matches!(first.token, Token::LeftBrace) {
        let (value, next) = parse_literal(&field, tokens, start, offset)?;
        check_literal(&field, &value, offset)?;
        return Ok((
            Predicate::Membership {
                field,
                values: vec![value],
            },
            next,
        ));
    }
    let mut index = start.saturating_add(1);
    let mut values = Vec::new();
    loop {
        let Some(current) = tokens.get(index) else {
            return Err(Error::Syntax {
                offset,
                message: "unterminated set, expected `}`".to_owned(),
            });
        };
        if matches!(current.token, Token::RightBrace) {
            index = index.saturating_add(1);
            break;
        }
        if !values.is_empty() {
            if !matches!(current.token, Token::Comma) {
                return Err(Error::Syntax {
                    offset: current.offset,
                    message: "expected `,` or `}` in a set".to_owned(),
                });
            }
            index = index.saturating_add(1);
        }
        let member_offset = tokens.get(index).map_or(offset, |token| token.offset);
        let (value, next) = parse_literal(&field, tokens, index, offset)?;
        check_literal(&field, &value, member_offset)?;
        values.push(value);
        if values.len() > limits.max_set_members {
            return Err(Error::SetMemberLimit {
                limit: limits.max_set_members,
            });
        }
        index = next;
    }
    if values.is_empty() {
        return Err(Error::Syntax {
            offset,
            message: "a set needs at least one member".to_owned(),
        });
    }
    Ok((Predicate::Membership { field, values }, index))
}
