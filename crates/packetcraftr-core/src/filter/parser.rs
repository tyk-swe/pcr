// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Bounded parsing and postfix-program compilation for display filters.

use super::ast::{Op, Predicate};
use super::error::Error;
use super::lexer::{CompareOperator, Spanned, Token, tokenize};
use super::literal::{self, Literal};
use super::path::{self, FieldRef, FieldSource, FrameField, Resolved, StreamTransport};
use crate::field::FieldKind;
use crate::registry::Registry;

pub const DEFAULT_MAX_FILTER_BYTES: usize = 64 * 1024;
/// Absolute parenthesis nesting accepted by the display-filter parser.
pub const MAX_FILTER_NESTING: usize = 64;
/// Absolute number of comparisons accepted in one display filter.
pub const MAX_FILTER_TERMS: usize = 1024;
/// Absolute number of members accepted in one `in { .. }` set.
pub const MAX_FILTER_SET_MEMBERS: usize = 1024;

/// Bounds applied while compiling a display filter.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Options {
    pub max_bytes: usize,
    pub max_nesting: usize,
    pub max_terms: usize,
    pub max_set_members: usize,
}

impl Default for Options {
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
    /// The filter reads `tcp.stream` or `udp.stream`.
    ///
    /// Callers that prepare indexes per transport inspect
    /// [`tcp_stream`](Self::tcp_stream) and [`udp_stream`](Self::udp_stream)
    /// instead.
    pub stream_index: bool,
    /// The filter reads `tcp.stream`, so TCP conversation indexes are needed.
    pub tcp_stream: bool,
    /// The filter reads `udp.stream`, so UDP conversation indexes are needed.
    pub udp_stream: bool,
    /// The filter reads `frame.time_epoch`, so frames without captured time
    /// must be diagnosed by the caller.
    pub timestamp: bool,
}

impl Requirements {
    fn require_stream(&mut self, transport: StreamTransport) {
        self.stream_index = true;
        match transport {
            StreamTransport::Tcp => self.tcp_stream = true,
            StreamTransport::Udp => self.udp_stream = true,
        }
    }
}

/// A boolean operator waiting for its operands.
///
/// Only these three can wait: a predicate is pushed straight onto the program,
/// so the operator stack has no way to hold one.
#[derive(Clone, Copy)]
enum Operator {
    Not,
    And,
    Or,
}

impl Operator {
    /// Binding power. `not` binds tightest, then `and`, then `or`, matching
    /// the conventional reading of `a || b && c`.
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

/// One entry on the operator stack.
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
    options: &'a Options,
    program: Vec<Op>,
    operators: Vec<Pending>,
    requirements: Requirements,
    expect_operand: bool,
    depth: usize,
    terms: usize,
    index: usize,
}

/// Compiles a display filter into postfix form.
///
/// Uses an explicit operand/operator stack rather than recursive descent, so
/// parser stack depth is constant no matter how deeply the source nests; the
/// configured nesting bound then caps the operator stack itself.
pub(super) fn compile(
    source: &str,
    registry: &Registry,
    options: &Options,
) -> Result<Compiled, Error> {
    validate_options(source, options)?;
    let tokens = tokenize(source)?;
    Compiler::new(&tokens, registry, options).compile(source.len())
}

fn validate_options(source: &str, options: &Options) -> Result<(), Error> {
    if source.len() > options.max_bytes {
        return Err(Error::SizeLimit {
            actual: source.len(),
            limit: options.max_bytes,
        });
    }
    if source.trim().is_empty() {
        return Err(Error::Empty);
    }
    if options.max_nesting > MAX_FILTER_NESTING {
        return Err(Error::InvalidNestingLimit {
            value: options.max_nesting,
            maximum: MAX_FILTER_NESTING,
        });
    }
    if options.max_terms > MAX_FILTER_TERMS {
        return Err(Error::InvalidTermLimit {
            value: options.max_terms,
            maximum: MAX_FILTER_TERMS,
        });
    }
    if options.max_set_members > MAX_FILTER_SET_MEMBERS {
        return Err(Error::InvalidSetMemberLimit {
            value: options.max_set_members,
            maximum: MAX_FILTER_SET_MEMBERS,
        });
    }
    Ok(())
}

impl<'a> Compiler<'a> {
    fn new(tokens: &'a [Spanned], registry: &'a Registry, options: &'a Options) -> Self {
        Self {
            tokens,
            registry,
            options,
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
        #[expect(
            clippy::indexing_slicing,
            reason = "compile only dispatches here while self.index < self.tokens.len()"
        )]
        let Spanned { token, offset } = &self.tokens[self.index];
        match token {
            Token::LeftParen => {
                self.depth = self.depth.saturating_add(1);
                if self.depth > self.options.max_nesting {
                    return Err(Error::NestingLimit {
                        limit: self.options.max_nesting,
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
                if self.terms > self.options.max_terms {
                    return Err(Error::TermLimit {
                        limit: self.options.max_terms,
                    });
                }
                let (predicate, next) = parse_predicate(
                    self.tokens,
                    self.index,
                    self.registry,
                    self.options,
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
        #[expect(
            clippy::indexing_slicing,
            reason = "compile only dispatches here while self.index < self.tokens.len()"
        )]
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

/// Parses one comparison, membership test, or presence test.
///
/// Returns the predicate and the index of the first token after it.
fn parse_predicate(
    tokens: &[Spanned],
    start: usize,
    registry: &Registry,
    options: &Options,
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
    parse_field_predicate(tokens, index, field, options)
}

enum Subject {
    Field { field: FieldRef, index: usize },
    Predicate(Predicate, usize),
}

fn parse_subject(tokens: &[Spanned], start: usize, registry: &Registry) -> Result<Subject, Error> {
    #[expect(
        clippy::indexing_slicing,
        reason = "start is the index of the Word token consume_operand already read"
    )]
    let Spanned { token, offset } = &tokens[start];
    let offset = *offset;
    let Token::Word(word) = token else {
        return Err(Error::Syntax {
            offset,
            message: "expected a field path".to_owned(),
        });
    };
    let resolved = path::resolve(word, registry, offset)?;
    let index = start.saturating_add(1);

    let field = match resolved {
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
                return Err(Error::UnsliceableField {
                    offset: *slice_offset,
                    path: word.clone(),
                });
            }
            if let Some(Spanned {
                token: Token::Compare(_) | Token::In | Token::Contains,
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
    options: &Options,
) -> Result<(Predicate, usize), Error> {
    match tokens.get(index) {
        Some(Spanned {
            token: Token::Compare(operator),
            offset: operator_offset,
        }) => {
            let (value, next) = parse_literal(tokens, index.saturating_add(1), *operator_offset)?;
            check_literal(&field, &value, *operator_offset)?;
            // Prefixes support membership only.
            if value.is_prefix()
                && !matches!(operator, CompareOperator::Equal | CompareOperator::NotEqual)
            {
                return Err(Error::OrderedPrefixComparison {
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
            let (needle, next) = parse_literal(tokens, index.saturating_add(1), *operator_offset)?;
            check_searchable(&field, &needle, *operator_offset)?;
            Ok((Predicate::Contains { field, needle }, next))
        }
        Some(Spanned {
            token: Token::In,
            offset: operator_offset,
        }) => parse_membership(
            tokens,
            index.saturating_add(1),
            field,
            options,
            *operator_offset,
        ),
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
    options: &Options,
    offset: usize,
) -> Result<(Predicate, usize), Error> {
    let Some(first) = tokens.get(start) else {
        return Err(Error::Syntax {
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
        let (value, next) = parse_literal(tokens, index, offset)?;
        check_literal(&field, &value, member_offset)?;
        values.push(value);
        if values.len() > options.max_set_members {
            return Err(Error::SetMemberLimit {
                limit: options.max_set_members,
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
        Token::Word(word) => literal::parse(word)
            // Remaining unquoted words are text literals.
            .unwrap_or_else(|| Literal::Text(word.clone())),
        other => {
            return Err(Error::Syntax {
                offset: *offset,
                message: format!("expected a value, found {}", describe(other)),
            });
        }
    };
    Ok((value, index.saturating_add(1)))
}

/// Rejects a literal that no value of the field's declared kinds could match.
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

/// Rejects a `contains` whose field is not a byte haystack, or whose needle is
/// not a byte sequence.
///
/// Without this, a mistyped `contains` compiles and then filters out every
/// packet, which reads as "no matches" rather than as the mistake it is.
fn check_searchable(field: &FieldRef, needle: &Literal, offset: usize) -> Result<(), Error> {
    if !literal::searchable_needle(needle) {
        return Err(incompatible(field, needle, offset));
    }
    if field.specs.is_empty() {
        return Ok(());
    }
    if field
        .specs
        .iter()
        .any(|spec| literal::searchable(spec.kind))
    {
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
        Token::Compare(_) => "a comparison operator".to_owned(),
        Token::Word(word) => format!("`{word}`"),
        Token::Text(_) => "quoted text".to_owned(),
        Token::Slice(_) => "a byte slice".to_owned(),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

    use super::*;

    fn registry() -> std::sync::Arc<Registry> {
        crate::protocol::builtin::registry()
    }

    #[test]
    fn postfix_program_preserves_boolean_precedence_and_records_requirements() {
        let registry = registry();
        let compiled = compile(
            "frame.time_epoch >= 0 || tcp.stream == 1 && !udp.stream == 2",
            &registry,
            &Options::default(),
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
        let registry = registry();
        assert!(matches!(
            compile(
                "ipv4",
                &registry,
                &Options {
                    max_bytes: 3,
                    ..Options::default()
                }
            ),
            Err(Error::SizeLimit {
                actual: 4,
                limit: 3
            })
        ));
        assert!(matches!(
            compile(" ", &registry, &Options::default()),
            Err(Error::Empty)
        ));
        assert!(matches!(
            compile(
                "ipv4",
                &registry,
                &Options {
                    max_nesting: MAX_FILTER_NESTING + 1,
                    ..Options::default()
                }
            ),
            Err(Error::InvalidNestingLimit { .. })
        ));
        assert!(matches!(
            compile(
                "ipv4",
                &registry,
                &Options {
                    max_terms: MAX_FILTER_TERMS + 1,
                    ..Options::default()
                }
            ),
            Err(Error::InvalidTermLimit { .. })
        ));
        assert!(matches!(
            compile(
                "ipv4",
                &registry,
                &Options {
                    max_set_members: MAX_FILTER_SET_MEMBERS + 1,
                    ..Options::default()
                }
            ),
            Err(Error::InvalidSetMemberLimit { .. })
        ));
        assert!(matches!(
            compile(
                "((ipv4))",
                &registry,
                &Options {
                    max_nesting: 1,
                    ..Options::default()
                }
            ),
            Err(Error::NestingLimit { limit: 1 })
        ));
        assert!(matches!(
            compile(
                "ipv4 && tcp",
                &registry,
                &Options {
                    max_terms: 1,
                    ..Options::default()
                }
            ),
            Err(Error::TermLimit { limit: 1 })
        ));
        assert!(matches!(
            compile(
                "tcp.port in {1, 2}",
                &registry,
                &Options {
                    max_set_members: 1,
                    ..Options::default()
                }
            ),
            Err(Error::SetMemberLimit { limit: 1 })
        ));
    }

    #[test]
    fn structural_syntax_errors_identify_the_rejected_construct() {
        let registry = registry();
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
            let error = match compile(source, &registry, &Options::default()) {
                Ok(_) => panic!("{source} unexpectedly compiled"),
                Err(error) => error,
            };
            assert!(error.to_string().contains(expected), "{source}: {error}");
        }
    }

    #[test]
    fn incompatible_prefix_and_contains_operations_fail_during_compilation() {
        let registry = registry();
        assert!(matches!(
            compile("ipv4.source > 192.0.2.0/24", &registry, &Options::default()),
            Err(Error::OrderedPrefixComparison { .. })
        ));
        assert!(matches!(
            compile("ipv4.source == 7", &registry, &Options::default()),
            Err(Error::IncompatibleLiteral { .. })
        ));
        assert!(matches!(
            compile(
                "tcp.source_port contains \"x\"",
                &registry,
                &Options::default()
            ),
            Err(Error::IncompatibleLiteral { .. })
        ));
        assert!(matches!(
            compile("raw.bytes contains 1", &registry, &Options::default()),
            Err(Error::IncompatibleLiteral { .. })
        ));
    }
}
