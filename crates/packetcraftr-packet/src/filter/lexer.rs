// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::ast::Operator;
use super::error::FilterError;

/// One lexical unit with the byte offset it started at.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Token {
    pub(super) offset: usize,
    pub(super) kind: TokenKind,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum TokenKind {
    /// A protocol name, optionally followed by `.field`.
    Path(String),
    Operator(Operator),
    /// The exact text of a literal, already unquoted.
    Value(String),
    Not,
    And,
    Or,
    OpenParen,
    CloseParen,
}

/// Splits a filter into tokens.
///
/// Literals are lexed by position rather than by shape: the run after a
/// comparison operator is taken verbatim. Addresses, prefixes, and MAC
/// addresses all contain characters that would otherwise need their own
/// lexical rules, and only the compiler knows which field kind a literal must
/// satisfy.
pub(super) fn tokenize(input: &str) -> Result<Vec<Token>, FilterError> {
    let bytes = input.as_bytes();
    let mut tokens = Vec::new();
    let mut index = 0;
    while index < bytes.len() {
        let byte = bytes[index];
        if byte.is_ascii_whitespace() {
            index += 1;
            continue;
        }
        let offset = index;
        match byte {
            b'(' => {
                tokens.push(Token {
                    offset,
                    kind: TokenKind::OpenParen,
                });
                index += 1;
            }
            b')' => {
                tokens.push(Token {
                    offset,
                    kind: TokenKind::CloseParen,
                });
                index += 1;
            }
            b'&' | b'|' => {
                if bytes.get(index + 1) != Some(&byte) {
                    return Err(FilterError::Syntax {
                        offset,
                        message: format!(
                            "expected {}{} for a logical operator",
                            byte as char, byte as char
                        ),
                    });
                }
                tokens.push(Token {
                    offset,
                    kind: if byte == b'&' {
                        TokenKind::And
                    } else {
                        TokenKind::Or
                    },
                });
                index += 2;
            }
            b'!' if bytes.get(index + 1) == Some(&b'=') => {
                index = push_operator(&mut tokens, offset, Operator::NotEqual, index + 2);
                index = take_value(input, index, offset, &mut tokens)?;
            }
            b'!' => {
                tokens.push(Token {
                    offset,
                    kind: TokenKind::Not,
                });
                index += 1;
            }
            b'=' => {
                if bytes.get(index + 1) != Some(&b'=') {
                    return Err(FilterError::Syntax {
                        offset,
                        message: "expected == for an equality comparison".to_owned(),
                    });
                }
                index = push_operator(&mut tokens, offset, Operator::Equal, index + 2);
                index = take_value(input, index, offset, &mut tokens)?;
            }
            b'<' | b'>' => {
                let equal = bytes.get(index + 1) == Some(&b'=');
                let operator = match (byte == b'<', equal) {
                    (true, false) => Operator::Less,
                    (true, true) => Operator::LessOrEqual,
                    (false, false) => Operator::Greater,
                    (false, true) => Operator::GreaterOrEqual,
                };
                let next = index + if equal { 2 } else { 1 };
                index = push_operator(&mut tokens, offset, operator, next);
                index = take_value(input, index, offset, &mut tokens)?;
            }
            byte if is_path_byte(byte) => {
                let end = bytes[index..]
                    .iter()
                    .position(|byte| !is_path_byte(*byte))
                    .map_or(bytes.len(), |length| index + length);
                tokens.push(Token {
                    offset,
                    kind: TokenKind::Path(input[index..end].to_owned()),
                });
                index = end;
            }
            byte => {
                return Err(FilterError::Syntax {
                    offset,
                    message: format!("unexpected character {:?}", byte as char),
                });
            }
        }
    }
    Ok(tokens)
}

fn push_operator(tokens: &mut Vec<Token>, offset: usize, operator: Operator, next: usize) -> usize {
    tokens.push(Token {
        offset,
        kind: TokenKind::Operator(operator),
    });
    next
}

fn is_path_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.')
}

/// Reads the literal that follows a comparison operator.
fn take_value(
    input: &str,
    start: usize,
    operator_offset: usize,
    tokens: &mut Vec<Token>,
) -> Result<usize, FilterError> {
    let bytes = input.as_bytes();
    let mut index = start;
    while index < bytes.len() && bytes[index].is_ascii_whitespace() {
        index += 1;
    }
    if index >= bytes.len() {
        return Err(FilterError::Syntax {
            offset: operator_offset,
            message: "comparison has no value".to_owned(),
        });
    }
    let offset = index;
    if matches!(bytes[index], b'"' | b'\'') {
        let quote = bytes[index];
        let close = bytes[index + 1..]
            .iter()
            .position(|byte| *byte == quote)
            .ok_or_else(|| FilterError::Syntax {
                offset,
                message: format!("unterminated {} quoted value", quote as char),
            })?;
        let end = index + 1 + close;
        tokens.push(Token {
            offset,
            kind: TokenKind::Value(input[index + 1..end].to_owned()),
        });
        return Ok(end + 1);
    }
    let end = bytes[index..]
        .iter()
        .position(|byte| byte.is_ascii_whitespace() || matches!(byte, b')' | b'(' | b'&' | b'|'))
        .map_or(bytes.len(), |length| index + length);
    if end == index {
        return Err(FilterError::Syntax {
            offset,
            message: "comparison has no value".to_owned(),
        });
    }
    tokens.push(Token {
        offset,
        kind: TokenKind::Value(input[index..end].to_owned()),
    });
    Ok(end)
}
