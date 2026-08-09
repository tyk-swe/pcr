// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Bounded parsing and postfix-program compilation for display filters.

use super::super::field::FieldKind;
use super::super::registry::ProtocolRegistry;
use super::ast::{Op, Predicate};
use super::error::FilterError;
use super::lexer::{CompareOperator, Spanned, Token, tokenize};
use super::literal::{self, Literal};
use super::path::{self, FieldRef, FieldSource, Resolved};

pub const DEFAULT_MAX_FILTER_BYTES: usize = 64 * 1024;
/// Absolute parenthesis nesting accepted by the display-filter parser.
pub const MAX_FILTER_NESTING: usize = 64;
/// Absolute number of comparisons accepted in one display filter.
pub const MAX_FILTER_TERMS: usize = 1024;
/// Absolute number of members accepted in one `in { .. }` set.
pub const MAX_FILTER_SET_MEMBERS: usize = 1024;

/// Bounds applied while compiling a display filter.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FilterOptions {
    pub max_bytes: usize,
    pub max_nesting: usize,
    pub max_terms: usize,
    pub max_set_members: usize,
}

impl Default for FilterOptions {
    fn default() -> Self {
        Self {
            max_bytes: DEFAULT_MAX_FILTER_BYTES,
            max_nesting: MAX_FILTER_NESTING,
            max_terms: MAX_FILTER_TERMS,
            max_set_members: MAX_FILTER_SET_MEMBERS,
        }
    }
}

/// What a compiled filter needs from its caller beyond the packet itself.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct Requirements {
    /// The filter reads `tcp.stream` or `udp.stream`, so it only makes sense
    /// where a conversation index is being maintained.
    pub stream_index: bool,
}

/// Binding power of the boolean operators. `not` binds tightest, then `and`,
/// then `or`, matching the conventional reading of `a || b && c`.
fn precedence(op: &Op) -> u8 {
    match op {
        Op::Not => 3,
        Op::And => 2,
        Op::Or => 1,
        Op::Leaf(_) => 0,
    }
}

/// One entry on the operator stack.
enum Pending {
    Operator(Op),
    LeftParen,
}

pub(super) struct Compiled {
    pub(super) program: Vec<Op>,
    pub(super) requirements: Requirements,
}

/// Compiles a display filter into postfix form.
///
/// Uses an explicit operand/operator stack rather than recursive descent, so
/// parser stack depth is constant no matter how deeply the source nests; the
/// configured nesting bound then caps the operator stack itself.
pub(super) fn compile(
    source: &str,
    registry: &ProtocolRegistry,
    options: &FilterOptions,
) -> Result<Compiled, FilterError> {
    // Reject oversized input before scanning it.
    if source.len() > options.max_bytes {
        return Err(FilterError::SizeLimit {
            actual: source.len(),
            limit: options.max_bytes,
        });
    }
    if source.trim().is_empty() {
        return Err(FilterError::Empty);
    }
    if options.max_nesting > MAX_FILTER_NESTING {
        return Err(FilterError::InvalidNestingLimit {
            value: options.max_nesting,
            maximum: MAX_FILTER_NESTING,
        });
    }
    if options.max_terms > MAX_FILTER_TERMS {
        return Err(FilterError::InvalidTermLimit {
            value: options.max_terms,
            maximum: MAX_FILTER_TERMS,
        });
    }
    if options.max_set_members > MAX_FILTER_SET_MEMBERS {
        return Err(FilterError::InvalidSetMemberLimit {
            value: options.max_set_members,
            maximum: MAX_FILTER_SET_MEMBERS,
        });
    }

    let tokens = tokenize(source)?;
    let mut program = Vec::new();
    let mut operators: Vec<Pending> = Vec::new();
    let mut requirements = Requirements::default();
    let mut expect_operand = true;
    let mut depth = 0_usize;
    let mut terms = 0_usize;
    let mut index = 0_usize;

    while index < tokens.len() {
        let Spanned { token, offset } = &tokens[index];
        let offset = *offset;
        if expect_operand {
            match token {
                Token::LeftParen => {
                    depth += 1;
                    if depth > options.max_nesting {
                        return Err(FilterError::NestingLimit {
                            limit: options.max_nesting,
                        });
                    }
                    operators.push(Pending::LeftParen);
                    index += 1;
                }
                Token::Not => {
                    operators.push(Pending::Operator(Op::Not));
                    index += 1;
                }
                Token::Word(_) => {
                    terms += 1;
                    if terms > options.max_terms {
                        return Err(FilterError::TermLimit {
                            limit: options.max_terms,
                        });
                    }
                    let (predicate, next) =
                        parse_predicate(&tokens, index, registry, options, &mut requirements)?;
                    program.push(Op::Leaf(predicate));
                    index = next;
                    expect_operand = false;
                }
                other => {
                    return Err(FilterError::Syntax {
                        offset,
                        message: format!("expected a field or `(`, found {}", describe(other)),
                    });
                }
            }
            continue;
        }
        match token {
            Token::And | Token::Or => {
                let incoming = if matches!(token, Token::And) {
                    Op::And
                } else {
                    Op::Or
                };
                while let Some(Pending::Operator(top)) = operators.last() {
                    if precedence(top) < precedence(&incoming) {
                        break;
                    }
                    let Some(Pending::Operator(op)) = operators.pop() else {
                        break;
                    };
                    program.push(op);
                }
                operators.push(Pending::Operator(incoming));
                expect_operand = true;
                index += 1;
            }
            Token::RightParen => {
                if depth == 0 {
                    return Err(FilterError::Syntax {
                        offset,
                        message: "unmatched `)`".to_owned(),
                    });
                }
                loop {
                    match operators.pop() {
                        Some(Pending::Operator(op)) => program.push(op),
                        Some(Pending::LeftParen) => break,
                        None => {
                            return Err(FilterError::Syntax {
                                offset,
                                message: "unmatched `)`".to_owned(),
                            });
                        }
                    }
                }
                depth -= 1;
                index += 1;
            }
            other => {
                return Err(FilterError::Syntax {
                    offset,
                    message: format!("expected `&&`, `||`, or `)`, found {}", describe(other)),
                });
            }
        }
    }

    if expect_operand {
        return Err(FilterError::Syntax {
            offset: source.len(),
            message: "display filter ends where a field was expected".to_owned(),
        });
    }
    while let Some(pending) = operators.pop() {
        match pending {
            Pending::Operator(op) => program.push(op),
            Pending::LeftParen => {
                return Err(FilterError::Syntax {
                    offset: source.len(),
                    message: "unmatched `(`".to_owned(),
                });
            }
        }
    }
    Ok(Compiled {
        program,
        requirements,
    })
}

/// Parses one comparison, membership test, or presence test.
///
/// Returns the predicate and the index of the first token after it.
fn parse_predicate(
    tokens: &[Spanned],
    start: usize,
    registry: &ProtocolRegistry,
    options: &FilterOptions,
    requirements: &mut Requirements,
) -> Result<(Predicate, usize), FilterError> {
    let Spanned { token, offset } = &tokens[start];
    let offset = *offset;
    let Token::Word(word) = token else {
        return Err(FilterError::Syntax {
            offset,
            message: "expected a field path".to_owned(),
        });
    };
    let resolved = path::resolve(word, registry, offset)?;
    let mut index = start + 1;

    let mut field = match resolved {
        Resolved::Layer {
            protocol,
            occurrence,
        } => {
            // Bare protocols are presence tests, not comparable or sliceable fields.
            if let Some(Spanned {
                token: Token::Slice(_),
                offset: slice_offset,
            }) = tokens.get(index)
            {
                return Err(FilterError::UnsliceableField {
                    offset: *slice_offset,
                    path: word.clone(),
                });
            }
            if let Some(Spanned {
                token: Token::Compare(_) | Token::In | Token::Contains,
                offset: operator_offset,
            }) = tokens.get(index)
            {
                return Err(FilterError::Syntax {
                    offset: *operator_offset,
                    message: format!("`{word}` names a layer, not a field, so it has no value"),
                });
            }
            return Ok((
                Predicate::LayerPresent {
                    protocol,
                    occurrence,
                },
                index,
            ));
        }
        Resolved::Field(field) => field,
    };

    if let Some(Spanned {
        token: Token::Slice(contents),
        offset: slice_offset,
    }) = tokens.get(index)
    {
        path::attach_slice(&mut field, contents, *slice_offset)?;
        index += 1;
    }
    if matches!(field.source, FieldSource::Stream(_)) {
        requirements.stream_index = true;
    }

    match tokens.get(index) {
        Some(Spanned {
            token: Token::Compare(operator),
            offset: operator_offset,
        }) => {
            let (value, next) = parse_literal(tokens, index + 1, *operator_offset)?;
            check_literal(&field, &value, *operator_offset)?;
            // Prefixes support membership only.
            if value.is_prefix()
                && !matches!(operator, CompareOperator::Equal | CompareOperator::NotEqual)
            {
                return Err(FilterError::OrderedPrefixComparison {
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
            let (needle, next) = parse_literal(tokens, index + 1, *operator_offset)?;
            check_searchable(&field, &needle, *operator_offset)?;
            Ok((Predicate::Contains { field, needle }, next))
        }
        Some(Spanned {
            token: Token::In,
            offset: operator_offset,
        }) => parse_membership(tokens, index + 1, field, options, *operator_offset),
        _ => {
            let flag = field.is_flag();
            Ok((Predicate::Bare { field, flag }, index))
        }
    }
}

/// Parses either a braced set or a single prefix literal after `in`.
fn parse_membership(
    tokens: &[Spanned],
    start: usize,
    field: FieldRef,
    options: &FilterOptions,
    offset: usize,
) -> Result<(Predicate, usize), FilterError> {
    let Some(first) = tokens.get(start) else {
        return Err(FilterError::Syntax {
            offset,
            message: "`in` needs a value or a `{ .. }` set".to_owned(),
        });
    };
    if !matches!(first.token, Token::LeftBrace) {
        // Accept one unbraced `in` value.
        let (value, next) = parse_literal(tokens, start, offset)?;
        check_literal(&field, &value, offset)?;
        return Ok((
            Predicate::Membership {
                field,
                values: vec![value],
            },
            next,
        ));
    }
    let mut index = start + 1;
    let mut values = Vec::new();
    loop {
        let Some(current) = tokens.get(index) else {
            return Err(FilterError::Syntax {
                offset,
                message: "unterminated set, expected `}`".to_owned(),
            });
        };
        if matches!(current.token, Token::RightBrace) {
            index += 1;
            break;
        }
        if !values.is_empty() {
            if !matches!(current.token, Token::Comma) {
                return Err(FilterError::Syntax {
                    offset: current.offset,
                    message: "expected `,` or `}` in a set".to_owned(),
                });
            }
            index += 1;
        }
        let member_offset = tokens.get(index).map_or(offset, |token| token.offset);
        let (value, next) = parse_literal(tokens, index, offset)?;
        check_literal(&field, &value, member_offset)?;
        values.push(value);
        if values.len() > options.max_set_members {
            return Err(FilterError::SetMemberLimit {
                limit: options.max_set_members,
            });
        }
        index = next;
    }
    if values.is_empty() {
        return Err(FilterError::Syntax {
            offset,
            message: "a set needs at least one member".to_owned(),
        });
    }
    Ok((Predicate::Membership { field, values }, index))
}

fn parse_literal(
    tokens: &[Spanned],
    index: usize,
    operator_offset: usize,
) -> Result<(Literal, usize), FilterError> {
    let Some(Spanned { token, offset }) = tokens.get(index) else {
        return Err(FilterError::Syntax {
            offset: operator_offset,
            message: "expected a value".to_owned(),
        });
    };
    let value = match token {
        Token::Text(text) => Literal::Text(text.clone()),
        Token::Word(word) => literal::parse(word)
            // Remaining unquoted words are text literals.
            .unwrap_or_else(|| Literal::Text(word.clone())),
        other => {
            return Err(FilterError::Syntax {
                offset: *offset,
                message: format!("expected a value, found {}", describe(other)),
            });
        }
    };
    Ok((value, index + 1))
}

/// Rejects a literal that no value of the field's declared kinds could match.
fn check_literal(field: &FieldRef, value: &Literal, offset: usize) -> Result<(), FilterError> {
    if field.kinds.is_empty() {
        return Ok(());
    }
    if field
        .kinds
        .iter()
        .any(|spec| literal::compatible(*spec, value))
    {
        return Ok(());
    }
    Err(incompatible(field, value, offset))
}

/// Rejects a `contains` whose field is not a byte haystack, or whose needle is
/// not a byte sequence.
///
/// Without this, a mistyped `contains` compiles and then filters out every
/// packet, which reads as "no matches" rather than as the mistake it is.
fn check_searchable(field: &FieldRef, needle: &Literal, offset: usize) -> Result<(), FilterError> {
    if !literal::searchable_needle(needle) {
        return Err(incompatible(field, needle, offset));
    }
    if field.kinds.is_empty() {
        return Ok(());
    }
    if field
        .kinds
        .iter()
        .any(|spec| literal::searchable(spec.kind))
    {
        return Ok(());
    }
    Err(incompatible(field, needle, offset))
}

fn incompatible(field: &FieldRef, value: &Literal, offset: usize) -> FilterError {
    FilterError::IncompatibleLiteral {
        offset,
        path: field.path.clone(),
        kind: literal::kind_name(
            field
                .kinds
                .first()
                .map_or(FieldKind::Bytes, |spec| spec.kind),
        ),
        literal: value.to_string(),
    }
}

fn describe(token: &Token) -> String {
    match token {
        Token::LeftParen => "`(`".to_owned(),
        Token::RightParen => "`)`".to_owned(),
        Token::LeftBrace => "`{`".to_owned(),
        Token::RightBrace => "`}`".to_owned(),
        Token::Comma => "`,`".to_owned(),
        Token::And => "`&&`".to_owned(),
        Token::Or => "`||`".to_owned(),
        Token::Not => "`!`".to_owned(),
        Token::In => "`in`".to_owned(),
        Token::Contains => "`contains`".to_owned(),
        Token::Compare(_) => "a comparison operator".to_owned(),
        Token::Word(word) => format!("`{word}`"),
        Token::Text(_) => "quoted text".to_owned(),
        Token::Slice(_) => "a byte slice".to_owned(),
    }
}
