// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::error::Error;

/// Comparison operators accepted by the display-filter grammar.
///
/// Each has a symbolic and a worded spelling so the same filter reads the same
/// way whether it was typed at a shell prompt or embedded in a document.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum CompareOperator {
    Equal,
    NotEqual,
    Greater,
    GreaterOrEqual,
    Less,
    LessOrEqual,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum Token {
    LeftParen,
    RightParen,
    LeftBrace,
    RightBrace,
    Comma,
    And,
    Or,
    Not,
    In,
    Contains,
    Compare(CompareOperator),
    /// An unquoted run of path, number, address, or keyword characters. The
    /// parser decides whether it names a field or spells a literal.
    Word(String),
    /// A quoted string, already unescaped. Always a text literal, never a path.
    Text(String),
    /// The raw contents of a `[..]` byte-slice suffix.
    Slice(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Spanned {
    pub(super) token: Token,
    pub(super) offset: usize,
}

/// Characters that may appear unquoted inside a path or literal.
///
/// Deliberately excludes every operator and delimiter character, so `a&&b`,
/// `tcp.port==443`, and `x[0:2]` tokenize correctly without whitespace. `:`
/// carries IPv6 and MAC literals, `/` carries prefix lengths, `#` selects a
/// layer occurrence, and `-` carries negative numbers and dashed MACs.
fn is_word_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b':' | b'/' | b'#' | b'-')
}

fn syntax(offset: usize, message: impl Into<String>) -> Error {
    Error::Syntax {
        offset,
        message: message.into(),
    }
}

/// Splits a display filter into tokens.
///
/// Operates on bytes rather than characters: every token character is ASCII,
/// and any non-ASCII byte can only appear inside a quoted string, where it is
/// copied through untouched.
pub(super) fn tokenize(source: &str) -> Result<Vec<Spanned>, Error> {
    let bytes = source.as_bytes();
    let mut tokens = Vec::new();
    let mut index = 0;
    while let Some(&byte) = bytes.get(index) {
        let offset = index;
        if byte.is_ascii_whitespace() {
            index = index.saturating_add(1);
            continue;
        }
        let token = match byte {
            b'(' | b')' | b'{' | b'}' | b',' => {
                index = index.saturating_add(1);
                match byte {
                    b'(' => Token::LeftParen,
                    b')' => Token::RightParen,
                    b'{' => Token::LeftBrace,
                    b'}' => Token::RightBrace,
                    _ => Token::Comma,
                }
            }
            b'[' => {
                let (contents, next) = read_slice(bytes, index)?;
                index = next;
                Token::Slice(contents)
            }
            b'"' => {
                let (contents, next) = read_quoted(source, index)?;
                index = next;
                Token::Text(contents)
            }
            b'&' | b'|' => {
                let expected = byte;
                if bytes.get(index.saturating_add(1)) != Some(&expected) {
                    let symbol = char::from(expected);
                    return Err(syntax(
                        offset,
                        format!("expected `{symbol}{symbol}`, not a single `{symbol}`"),
                    ));
                }
                index = index.saturating_add(2);
                if expected == b'&' {
                    Token::And
                } else {
                    Token::Or
                }
            }
            b'=' => {
                if bytes.get(index.saturating_add(1)) != Some(&b'=') {
                    return Err(syntax(offset, "expected `==`, not a single `=`"));
                }
                index = index.saturating_add(2);
                Token::Compare(CompareOperator::Equal)
            }
            b'!' => {
                if bytes.get(index.saturating_add(1)) == Some(&b'=') {
                    index = index.saturating_add(2);
                    Token::Compare(CompareOperator::NotEqual)
                } else {
                    index = index.saturating_add(1);
                    Token::Not
                }
            }
            b'>' | b'<' => {
                let inclusive = bytes.get(index.saturating_add(1)) == Some(&b'=');
                index = index.saturating_add(if inclusive { 2 } else { 1 });
                Token::Compare(match (byte, inclusive) {
                    (b'>', false) => CompareOperator::Greater,
                    (b'>', true) => CompareOperator::GreaterOrEqual,
                    (_, false) => CompareOperator::Less,
                    (_, true) => CompareOperator::LessOrEqual,
                })
            }
            byte if is_word_byte(byte) => {
                let start = index;
                while bytes.get(index).is_some_and(|&byte| is_word_byte(byte)) {
                    index = index.saturating_add(1);
                }
                let word = &source[start..index];
                keyword(word).unwrap_or_else(|| Token::Word(word.to_owned()))
            }
            other => {
                return Err(syntax(
                    offset,
                    format!("unexpected character `{}`", char::from(other)),
                ));
            }
        };
        tokens.push(Spanned { token, offset });
    }
    Ok(tokens)
}

/// Recognizes the worded spellings of operators. Matching is case-insensitive
/// so `AND` and `and` behave alike, but field paths stay case-sensitive.
fn keyword(word: &str) -> Option<Token> {
    let lowered = word.to_ascii_lowercase();
    Some(match lowered.as_str() {
        "and" => Token::And,
        "or" => Token::Or,
        "not" => Token::Not,
        "in" => Token::In,
        "contains" => Token::Contains,
        "eq" => Token::Compare(CompareOperator::Equal),
        "ne" => Token::Compare(CompareOperator::NotEqual),
        "gt" => Token::Compare(CompareOperator::Greater),
        "ge" => Token::Compare(CompareOperator::GreaterOrEqual),
        "lt" => Token::Compare(CompareOperator::Less),
        "le" => Token::Compare(CompareOperator::LessOrEqual),
        _ => return None,
    })
}

/// Reads a `[..]` suffix, returning its contents and the index after the `]`.
/// Slice contents are parsed later, once the field it applies to is known.
fn read_slice(bytes: &[u8], open: usize) -> Result<(String, usize), Error> {
    let start = open.saturating_add(1);
    let mut index = start;
    while let Some(&byte) = bytes.get(index) {
        if byte == b']' {
            break;
        }
        if byte == b'[' {
            return Err(syntax(index, "byte slices do not nest"));
        }
        index = index.saturating_add(1);
    }
    if index >= bytes.len() {
        return Err(syntax(open, "unterminated byte slice, expected `]`"));
    }
    #[expect(
        clippy::indexing_slicing,
        reason = "start <= index <= bytes.len(): index starts at start and only advances while it addresses a byte"
    )]
    let contents = String::from_utf8(bytes[start..index].to_vec())
        .map_err(|_| syntax(open, "byte slice bounds must be ASCII"))?;
    Ok((contents, index.saturating_add(1)))
}

/// Reads a double-quoted string, honouring `\\` and `\"` escapes.
fn read_quoted(source: &str, open: usize) -> Result<(String, usize), Error> {
    let bytes = source.as_bytes();
    let mut contents = Vec::new();
    let mut index = open.saturating_add(1);
    while let Some(&byte) = bytes.get(index) {
        match byte {
            b'"' => {
                let text = String::from_utf8(contents)
                    .map_err(|_| syntax(open, "quoted text must be valid UTF-8"))?;
                return Ok((text, index.saturating_add(1)));
            }
            b'\\' => {
                let Some(escaped) = bytes.get(index.saturating_add(1)) else {
                    return Err(syntax(index, "trailing escape in quoted text"));
                };
                match escaped {
                    b'\\' | b'"' => contents.push(*escaped),
                    other => {
                        return Err(syntax(
                            index,
                            format!("unsupported escape `\\{}`", char::from(*other)),
                        ));
                    }
                }
                index = index.saturating_add(2);
            }
            other => {
                contents.push(other);
                index = index.saturating_add(1);
            }
        }
    }
    Err(syntax(open, "unterminated quoted text, expected `\"`"))
}
