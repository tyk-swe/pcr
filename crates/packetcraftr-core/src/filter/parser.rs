// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use bytes::Bytes;

use super::ast::{Op, Predicate};
use super::comparison::Needle;
use super::error::Error;
use super::lexer::{CompareOperator, Spanned, Token, tokenize};
use super::literal::{self, Literal};
use super::path::{self, FieldRef, FieldSource, FrameField, Resolved, StreamTransport};
use crate::field::FieldKind;
use crate::registry::Registry;

pub const DEFAULT_MAX_FILTER_BYTES: usize = 64 * 1024;
pub const MAX_FILTER_NESTING: usize = 64;
pub const MAX_FILTER_TERMS: usize = 1024;
pub const MAX_FILTER_SET_MEMBERS: usize = 1024;

/// Ceilings on one display filter, applied while compiling it.
///
/// Every value is honored as given. `max_nesting`, `max_terms`, and
/// `max_set_members` also have stable maxima, which
/// [`validate`](Self::validate) enforces; `max_bytes` has none.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Limits {
    pub max_bytes: usize,
    pub max_nesting: usize,
    pub max_terms: usize,
    pub max_set_members: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_bytes: DEFAULT_MAX_FILTER_BYTES,
            max_nesting: MAX_FILTER_NESTING,
            max_terms: MAX_FILTER_TERMS,
            max_set_members: MAX_FILTER_SET_MEMBERS,
        }
    }
}

impl Limits {
    /// Checks the ceilings against their stable maxima.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidNestingLimit`], [`Error::InvalidTermLimit`], or
    /// [`Error::InvalidSetMemberLimit`] when the matching ceiling exceeds its
    /// stable maximum.
    pub fn validate(&self) -> Result<(), Error> {
        if self.max_nesting > MAX_FILTER_NESTING {
            return Err(Error::InvalidNestingLimit {
                value: self.max_nesting,
                maximum: MAX_FILTER_NESTING,
            });
        }
        if self.max_terms > MAX_FILTER_TERMS {
            return Err(Error::InvalidTermLimit {
                value: self.max_terms,
                maximum: MAX_FILTER_TERMS,
            });
        }
        if self.max_set_members > MAX_FILTER_SET_MEMBERS {
            return Err(Error::InvalidSetMemberLimit {
                value: self.max_set_members,
                maximum: MAX_FILTER_SET_MEMBERS,
            });
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct Requirements {
    /// The filter reads `tcp.stream` or `udp.stream`.
    pub stream_index: bool,
    pub tcp_stream: bool,
    pub udp_stream: bool,
    pub timestamp: bool,
}

impl Requirements {
    /// Everything either operand requires.
    #[must_use]
    pub fn union(self, other: Self) -> Self {
        Self {
            stream_index: self.stream_index || other.stream_index,
            tcp_stream: self.tcp_stream || other.tcp_stream,
            udp_stream: self.udp_stream || other.udp_stream,
            timestamp: self.timestamp || other.timestamp,
        }
    }

    fn require_stream(&mut self, transport: StreamTransport) {
        self.stream_index = true;
        match transport {
            StreamTransport::Tcp => self.tcp_stream = true,
            StreamTransport::Udp => self.udp_stream = true,
        }
    }
}

#[derive(Clone, Copy)]
enum Operator {
    Not,
    And,
    Or,
}

impl Operator {
    const fn precedence(self) -> u8 {
        match self {
            Self::Not => 3,
            Self::And => 2,
            Self::Or => 1,
        }
    }

    const fn into_op(self) -> Op {
        match self {
            Self::Not => Op::Not,
            Self::And => Op::And,
            Self::Or => Op::Or,
        }
    }
}

enum Pending {
    Operator(Operator),
    LeftParen,
}

pub(super) struct Compiled {
    pub(super) program: Vec<Op>,
    pub(super) requirements: Requirements,
}

struct Compiler<'a> {
    tokens: &'a [Spanned],
    registry: &'a Registry,
    limits: &'a Limits,
    program: Vec<Op>,
    operators: Vec<Pending>,
    requirements: Requirements,
    expect_operand: bool,
    depth: usize,
    terms: usize,
    index: usize,
}

/// Uses an explicit operand/operator stack rather than recursive descent, so stack depth is constant.
pub(super) fn compile(
    source: &str,
    registry: &Registry,
    limits: &Limits,
) -> Result<Compiled, Error> {
    validate_limits(source, limits)?;
    let tokens = tokenize(source)?;
    Compiler::new(&tokens, registry, limits).compile(source.len())
}

fn validate_limits(source: &str, limits: &Limits) -> Result<(), Error> {
    if source.len() > limits.max_bytes {
        return Err(Error::SizeLimit {
            actual: source.len(),
            limit: limits.max_bytes,
        });
    }
    if source.trim().is_empty() {
        return Err(Error::Empty);
    }
    limits.validate()
}

impl<'a> Compiler<'a> {
    fn new(tokens: &'a [Spanned], registry: &'a Registry, limits: &'a Limits) -> Self {
        Self {
            tokens,
            registry,
            limits,
            program: Vec::new(),
            operators: Vec::new(),
            requirements: Requirements::default(),
            expect_operand: true,
            depth: 0,
            terms: 0,
            index: 0,
        }
    }

    fn compile(mut self, source_len: usize) -> Result<Compiled, Error> {
        while self.index < self.tokens.len() {
            if self.expect_operand {
                self.consume_operand()?;
            } else {
                self.consume_operator()?;
            }
        }
        self.finish(source_len)
    }

    fn consume_operand(&mut self) -> Result<(), Error> {
        // compile only dispatches here while self.index < self.tokens.len()
        let Spanned { token, offset } = &self.tokens[self.index];
        match token {
            Token::LeftParen => {
                self.depth = self.depth.saturating_add(1);
                if self.depth > self.limits.max_nesting {
                    return Err(Error::NestingLimit {
                        limit: self.limits.max_nesting,
                    });
                }
                self.operators.push(Pending::LeftParen);
                self.index = self.index.saturating_add(1);
            }
            Token::Not => {
                self.operators.push(Pending::Operator(Operator::Not));
                self.index = self.index.saturating_add(1);
            }
            Token::Word(_) => {
                self.terms = self.terms.saturating_add(1);
                if self.terms > self.limits.max_terms {
                    return Err(Error::TermLimit {
                        limit: self.limits.max_terms,
                    });
                }
                let (predicate, next) = parse_predicate(
                    self.tokens,
                    self.index,
                    self.registry,
                    self.limits,
                    &mut self.requirements,
                )?;
                self.program.push(Op::Leaf(predicate));
                self.index = next;
                self.expect_operand = false;
            }
            other => {
                return Err(Error::Syntax {
                    offset: *offset,
                    message: format!("expected a field or `(`, found {}", describe(other)),
                });
            }
        }
        Ok(())
    }

    fn consume_operator(&mut self) -> Result<(), Error> {
        // compile only dispatches here while self.index < self.tokens.len()
        let Spanned { token, offset } = &self.tokens[self.index];
        match token {
            Token::And | Token::Or => {
                let incoming = if matches!(token, Token::And) {
                    Operator::And
                } else {
                    Operator::Or
                };
                while let Some(Pending::Operator(top)) = self.operators.last() {
                    if top.precedence() < incoming.precedence() {
                        break;
                    }
                    let Some(Pending::Operator(operator)) = self.operators.pop() else {
                        break;
                    };
                    self.program.push(operator.into_op());
                }
                self.operators.push(Pending::Operator(incoming));
                self.expect_operand = true;
                self.index = self.index.saturating_add(1);
            }
            Token::RightParen => {
                if self.depth == 0 {
                    return Err(Error::Syntax {
                        offset: *offset,
                        message: "unmatched `)`".to_owned(),
                    });
                }
                loop {
                    match self.operators.pop() {
                        Some(Pending::Operator(operator)) => {
                            self.program.push(operator.into_op());
                        }
                        Some(Pending::LeftParen) => break,
                        None => {
                            return Err(Error::Syntax {
                                offset: *offset,
                                message: "unmatched `)`".to_owned(),
                            });
                        }
                    }
                }
                self.depth = self.depth.saturating_sub(1);
                self.index = self.index.saturating_add(1);
            }
            other => {
                return Err(Error::Syntax {
                    offset: *offset,
                    message: format!("expected `&&`, `||`, or `)`, found {}", describe(other)),
                });
            }
        }
        Ok(())
    }

    fn finish(mut self, source_len: usize) -> Result<Compiled, Error> {
        if self.expect_operand {
            return Err(Error::Syntax {
                offset: source_len,
                message: "display filter ends where a field was expected".to_owned(),
            });
        }
        while let Some(pending) = self.operators.pop() {
            match pending {
                Pending::Operator(operator) => self.program.push(operator.into_op()),
                Pending::LeftParen => {
                    return Err(Error::Syntax {
                        offset: source_len,
                        message: "unmatched `(`".to_owned(),
                    });
                }
            }
        }
        Ok(Compiled {
            program: self.program,
            requirements: self.requirements,
        })
    }
}

fn parse_predicate(
    tokens: &[Spanned],
    start: usize,
    registry: &Registry,
    limits: &Limits,
    requirements: &mut Requirements,
) -> Result<(Predicate, usize), Error> {
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
        if contents.is_empty() || !contents.bytes().all(|byte| byte.is_ascii_digit()) {
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
            Err(error) if next > index + 1 => return Err(error),
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
    if matches!(field.source, FieldSource::Frame(FrameField::TimeEpoch)) {
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

/// A decimal or `0x` hexadecimal number; `fallback` locates the error when the filter ends first.
fn unsigned_operand(
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

fn parse_literal(
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

fn check_literal(field: &FieldRef, value: &Literal, offset: usize) -> Result<(), Error> {
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
fn check_searchable(field: &FieldRef, needle: &Literal, offset: usize) -> Result<(), Error> {
    if field.specs.is_empty() {
        return Ok(());
    }
    if field.specs.iter().any(|spec| literal::searchable(*spec)) {
        return Ok(());
    }
    Err(incompatible(field, needle, offset))
}

fn incompatible(field: &FieldRef, value: &Literal, offset: usize) -> Error {
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
        Token::TextMatch(_) => "a text operator".to_owned(),
        Token::Ampersand => "`&`".to_owned(),
        Token::Compare(_) => "a comparison operator".to_owned(),
        Token::Word(word) => format!("`{word}`"),
        Token::Text(_) => "quoted text".to_owned(),
        Token::ByteString(_) => "a byte string".to_owned(),
        Token::Slice(_) => "a byte slice".to_owned(),
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn postfix_program_preserves_boolean_precedence_and_records_requirements() {
        let registry = crate::protocol::builtin::registry();
        let compiled = compile(
            "frame.time_epoch >= 0 || tcp.stream == 1 && !udp.stream == 2",
            &registry,
            &Limits::default(),
        )
        .expect("valid mixed-requirement filter compiles");

        assert_eq!(compiled.program.len(), 6);
        assert!(matches!(compiled.program[0], Op::Leaf(_)));
        assert!(matches!(compiled.program[1], Op::Leaf(_)));
        assert!(matches!(compiled.program[2], Op::Leaf(_)));
        assert!(matches!(compiled.program[3], Op::Not));
        assert!(matches!(compiled.program[4], Op::And));
        assert!(matches!(compiled.program[5], Op::Or));
        assert_eq!(
            compiled.requirements,
            Requirements {
                stream_index: true,
                tcp_stream: true,
                udp_stream: true,
                timestamp: true,
            }
        );
    }

    #[test]
    fn configured_parser_limits_fail_at_the_first_excess_item() {
        let registry = crate::protocol::builtin::registry();
        assert!(matches!(
            compile(
                "ipv4",
                &registry,
                &Limits {
                    max_bytes: 3,
                    ..Limits::default()
                }
            ),
            Err(Error::SizeLimit {
                actual: 4,
                limit: 3
            })
        ));
        assert!(matches!(
            compile(" ", &registry, &Limits::default()),
            Err(Error::Empty)
        ));
        assert!(matches!(
            compile(
                "ipv4",
                &registry,
                &Limits {
                    max_nesting: MAX_FILTER_NESTING + 1,
                    ..Limits::default()
                }
            ),
            Err(Error::InvalidNestingLimit { .. })
        ));
        assert!(matches!(
            compile(
                "ipv4",
                &registry,
                &Limits {
                    max_terms: MAX_FILTER_TERMS + 1,
                    ..Limits::default()
                }
            ),
            Err(Error::InvalidTermLimit { .. })
        ));
        assert!(matches!(
            compile(
                "ipv4",
                &registry,
                &Limits {
                    max_set_members: MAX_FILTER_SET_MEMBERS + 1,
                    ..Limits::default()
                }
            ),
            Err(Error::InvalidSetMemberLimit { .. })
        ));
        assert!(matches!(
            compile(
                "((ipv4))",
                &registry,
                &Limits {
                    max_nesting: 1,
                    ..Limits::default()
                }
            ),
            Err(Error::NestingLimit { limit: 1 })
        ));
        assert!(matches!(
            compile(
                "ipv4 && tcp",
                &registry,
                &Limits {
                    max_terms: 1,
                    ..Limits::default()
                }
            ),
            Err(Error::TermLimit { limit: 1 })
        ));
        assert!(matches!(
            compile(
                "tcp.port in {1, 2}",
                &registry,
                &Limits {
                    max_set_members: 1,
                    ..Limits::default()
                }
            ),
            Err(Error::SetMemberLimit { limit: 1 })
        ));
    }

    #[test]
    fn structural_syntax_errors_identify_the_rejected_construct() {
        let registry = crate::protocol::builtin::registry();
        let cases = [
            ("&& ipv4", "expected a field or `(`"),
            ("ipv4 &&", "ends where a field was expected"),
            ("ipv4)", "unmatched `)`"),
            ("(ipv4", "unmatched `(`"),
            ("ipv4 tcp", "expected `&&`, `||`, or `)`"),
            ("ipv4[0]", "cannot be sliced"),
            ("ipv4 == 1", "names a layer, not a field"),
            ("tcp.port in", "`in` needs a value"),
            ("tcp.port in {}", "set needs at least one member"),
            ("tcp.port in {1", "unterminated set"),
            ("tcp.port in {1 2}", "expected `,` or `}`"),
            ("tcp.port == }", "expected a value"),
        ];

        for (source, expected) in cases {
            let error = match compile(source, &registry, &Limits::default()) {
                Ok(_) => panic!("{source} unexpectedly compiled"),
                Err(error) => error,
            };
            assert!(error.to_string().contains(expected), "{source}: {error}");
        }
    }

    #[test]
    fn hex_looking_words_are_rejected_only_where_text_would_silently_become_ascii_bytes() {
        use crate::filter::path::FieldSpec;

        fn field(kinds: &[FieldKind]) -> FieldRef {
            FieldRef {
                source: FieldSource::Frame(FrameField::Number),
                slice: None,
                specs: kinds
                    .iter()
                    .map(|kind| FieldSpec::synthetic(*kind))
                    .collect(),
                path: "fixture".to_owned(),
            }
        }

        fn word(text: &str) -> Vec<Spanned> {
            vec![Spanned {
                token: Token::Word(text.to_owned()),
                offset: 7,
            }]
        }

        for kinds in [
            &[FieldKind::Bytes][..],
            &[FieldKind::Mac],
            &[FieldKind::Bytes, FieldKind::Mac],
        ] {
            for malformed in ["c000", "c0:0"] {
                assert!(
                    matches!(
                        parse_literal(&field(kinds), &word(malformed), 0, 0),
                        Err(Error::UnquotedByteWord {
                            offset: 7,
                            ref path,
                            ref literal,
                        }) if path == "fixture" && literal == malformed
                    ),
                    "{kinds:?} {malformed}"
                );
            }
            assert!(parse_literal(&field(kinds), &word("GET"), 0, 0).is_ok());
        }
        for kinds in [
            &[][..],
            &[FieldKind::Text],
            &[FieldKind::Bytes, FieldKind::Text],
            &[FieldKind::List],
        ] {
            for malformed in ["c000", "c0:0"] {
                assert!(
                    matches!(
                        parse_literal(&field(kinds), &word(malformed), 0, 0),
                        Ok((Literal::Text(ref text), 1)) if text == malformed
                    ),
                    "{kinds:?} {malformed}"
                );
            }
        }
    }

    #[test]
    fn incompatible_prefix_and_contains_operations_fail_during_compilation() {
        let registry = crate::protocol::builtin::registry();
        assert!(matches!(
            compile("ipv4.source > 192.0.2.0/24", &registry, &Limits::default()),
            Err(Error::OrderedPrefixComparison { .. })
        ));
        assert!(matches!(
            compile("ipv4.source == 7", &registry, &Limits::default()),
            Err(Error::IncompatibleLiteral { .. })
        ));
        assert!(matches!(
            compile(
                "tcp.source_port contains \"x\"",
                &registry,
                &Limits::default()
            ),
            Err(Error::IncompatibleLiteral { .. })
        ));
        assert!(matches!(
            compile("raw.bytes contains 1", &registry, &Limits::default()),
            Err(Error::IncompatibleLiteral { .. })
        ));
    }

    #[test]
    fn contains_refusals_report_the_operator_offset_field_kind_and_literal() {
        let registry = crate::protocol::builtin::registry();
        let cases = [
            ("raw.bytes contains 1", 10, "raw.bytes", "bytes", "1"),
            (
                "tcp.source_port contains \"x\"",
                16,
                "tcp.source_port",
                "an unsigned number",
                "\"x\"",
            ),
        ];

        for (source, offset, path, kind, literal) in cases {
            let error = match compile(source, &registry, &Limits::default()) {
                Ok(_) => panic!("{source} unexpectedly compiled"),
                Err(error) => error,
            };
            let Error::IncompatibleLiteral {
                offset: actual_offset,
                path: actual_path,
                kind: actual_kind,
                literal: actual_literal,
            } = error
            else {
                panic!("{source}: unexpected error {error}");
            };
            assert_eq!(actual_offset, offset, "{source}");
            assert_eq!(actual_path, path, "{source}");
            assert_eq!(actual_kind, kind, "{source}");
            assert_eq!(actual_literal, literal, "{source}");
        }
    }

    #[test]
    fn requirements_union_ors_each_flag_independently() {
        let none = Requirements::default();
        let flags: [fn(&mut Requirements); 4] = [
            |requirements| requirements.stream_index = true,
            |requirements| requirements.tcp_stream = true,
            |requirements| requirements.udp_stream = true,
            |requirements| requirements.timestamp = true,
        ];

        for (index, set) in flags.iter().enumerate() {
            let mut one = Requirements::default();
            set(&mut one);
            assert_ne!(one, none, "flag {index}");
            assert_eq!(one.union(none), one, "flag {index}");
            assert_eq!(none.union(one), one, "flag {index}");
            for (other_index, other_set) in flags.iter().enumerate() {
                let mut other = Requirements::default();
                other_set(&mut other);
                let mut both = one;
                other_set(&mut both);
                assert_eq!(one.union(other), both, "flags {index} and {other_index}");
            }
        }
        assert_eq!(none.union(none), none);
    }
}
