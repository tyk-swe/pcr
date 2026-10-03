// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::ast::Op;
use super::error::Error;
use super::lexer::{Spanned, Token, tokenize};
use super::limits::Limits;
use super::requirements::Requirements;
use crate::registry::Registry;

mod predicate;
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
                let (predicate, next) = predicate::parse(
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
