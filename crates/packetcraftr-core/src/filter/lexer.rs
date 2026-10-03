// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::comparison::TextMode;
use super::error::Error;

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
    /// `startswith`, `endswith`, `icontains`, or `iequals`.
    TextMatch(TextMode),
    /// A single `&`, which masks a field before it is compared.
    Ampersand,
    Compare(CompareOperator),
    Word(String),
    /// A quoted string, already unescaped. Always a text literal, never a path.
    Text(String),
    /// A `b"..."` literal, already unescaped. Its bytes need not be UTF-8.
    ByteString(Vec<u8>),
    Slice(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Spanned {
    pub(super) token: Token,
    pub(super) offset: usize,
}

fn is_word_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b':' | b'/' | b'#' | b'-')
}

fn syntax(offset: usize, message: impl Into<String>) -> Error {
    Error::Syntax {
        offset,
        message: message.into(),
    }
}

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
                let (contents, next) = read_slice(source, index)?;
                index = next;
                Token::Slice(contents)
            }
            b'"' => {
                let (contents, next) = read_quoted(source, offset, index, Quoting::Text)?;
                index = next;
                Token::Text(text_from(contents, offset)?)
            }
            // Only a lone `b` directly before a quote; any longer word stays an ordinary word.
            b'b' if bytes.get(index.saturating_add(1)) == Some(&b'"') => {
                let quote = index.saturating_add(1);
                let (contents, next) = read_quoted(source, offset, quote, Quoting::Bytes)?;
                index = next;
                Token::ByteString(contents)
            }
            b'&' if bytes.get(index.saturating_add(1)) != Some(&b'&') => {
                index = index.saturating_add(1);
                Token::Ampersand
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
            _ => {
                return Err(syntax(
                    offset,
                    format!("unexpected character `{}`", character_at(source, offset)),
                ));
            }
        };
        tokens.push(Spanned { token, offset });
    }
    Ok(tokens)
}

fn keyword(word: &str) -> Option<Token> {
    let lowered = word.to_ascii_lowercase();
    Some(match lowered.as_str() {
        "and" => Token::And,
        "or" => Token::Or,
        "not" => Token::Not,
        "in" => Token::In,
        "contains" => Token::Contains,
        "startswith" => Token::TextMatch(TextMode::Prefix),
        "endswith" => Token::TextMatch(TextMode::Suffix),
        "icontains" => Token::TextMatch(TextMode::ContainsFold),
        "iequals" => Token::TextMatch(TextMode::EqualsFold),
        "eq" => Token::Compare(CompareOperator::Equal),
        "ne" => Token::Compare(CompareOperator::NotEqual),
        "gt" => Token::Compare(CompareOperator::Greater),
        "ge" => Token::Compare(CompareOperator::GreaterOrEqual),
        "lt" => Token::Compare(CompareOperator::Less),
        "le" => Token::Compare(CompareOperator::LessOrEqual),
        _ => return None,
    })
}

fn character_at(source: &str, index: usize) -> char {
    source
        .get(index..)
        .and_then(|rest| rest.chars().next())
        .unwrap_or(char::REPLACEMENT_CHARACTER)
}

fn read_slice(source: &str, open: usize) -> Result<(String, usize), Error> {
    let bytes = source.as_bytes();
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
    // start and index follow and address the ASCII `[` and `]`, so both are char boundaries
    Ok((source[start..index].to_owned(), index.saturating_add(1)))
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Quoting {
    /// `\xNN` stays ASCII, so the contents remain valid UTF-8.
    Text,
    /// `\xNN` covers every byte.
    Bytes,
}

/// `literal` is where the literal starts, which is where an unterminated one is reported; `quote` addresses its opening `"`.
fn read_quoted(
    source: &str,
    literal: usize,
    quote: usize,
    quoting: Quoting,
) -> Result<(Vec<u8>, usize), Error> {
    let start = quote.saturating_add(1);
    let mut contents = Vec::new();
    // start follows the ASCII `"` at quote, so it is a char boundary
    let mut chars = source[start..].char_indices();
    while let Some((relative, character)) = chars.next() {
        let index = start.saturating_add(relative);
        match character {
            '"' => return Ok((contents, index.saturating_add(1))),
            '\\' => contents.push(read_escape(&mut chars, index, quoting)?),
            other => {
                let mut buffer = [0; 4];
                contents.extend_from_slice(other.encode_utf8(&mut buffer).as_bytes());
            }
        }
    }
    let what = match quoting {
        Quoting::Text => "quoted text",
        Quoting::Bytes => "byte string",
    };
    Err(syntax(
        literal,
        format!("unterminated {what}, expected `\"`"),
    ))
}

/// `offset` addresses the backslash, which is where every escape error points.
fn read_escape(
    chars: &mut std::str::CharIndices<'_>,
    offset: usize,
    quoting: Quoting,
) -> Result<u8, Error> {
    let Some((_, escaped)) = chars.next() else {
        return Err(syntax(offset, "trailing escape in quoted text"));
    };
    Ok(match escaped {
        '\\' => b'\\',
        '"' => b'"',
        'r' => b'\r',
        'n' => b'\n',
        't' => b'\t',
        '0' => 0,
        'x' => {
            let mut value = 0_u8;
            for _ in 0..2 {
                let digit = chars
                    .next()
                    .and_then(|(_, digit)| digit.to_digit(16))
                    .and_then(|digit| u8::try_from(digit).ok())
                    .ok_or_else(|| syntax(offset, "`\\x` escape needs two hexadecimal digits"))?;
                value = (value << 4) | digit;
            }
            if quoting == Quoting::Text && !value.is_ascii() {
                return Err(syntax(
                    offset,
                    format!(
                        "escape `\\x{value:02x}` is not ASCII; write non-ASCII bytes in a `b\"...\"` literal"
                    ),
                ));
            }
            value
        }
        other => return Err(syntax(offset, format!("unsupported escape `\\{other}`"))),
    })
}

fn text_from(contents: Vec<u8>, offset: usize) -> Result<String, Error> {
    String::from_utf8(contents).map_err(|_| syntax(offset, "quoted text is not valid UTF-8"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn only(source: &str) -> Token {
        let mut tokens = tokenize(source).expect("fixture tokenizes");
        assert_eq!(tokens.len(), 1, "{source}");
        tokens.remove(0).token
    }

    fn kinds(source: &str) -> Vec<Token> {
        tokenize(source)
            .expect("fixture tokenizes")
            .into_iter()
            .map(|spanned| spanned.token)
            .collect()
    }

    #[test]
    fn a_b_is_a_byte_string_only_as_a_lone_word_before_a_quote() {
        assert_eq!(only("b"), Token::Word("b".to_owned()));
        assert_eq!(only("b.x"), Token::Word("b.x".to_owned()));
        assert_eq!(only("ab"), Token::Word("ab".to_owned()));
        assert_eq!(
            kinds("ab\"x\""),
            [Token::Word("ab".to_owned()), Token::Text("x".to_owned())]
        );
        assert_eq!(
            kinds("b \"x\""),
            [Token::Word("b".to_owned()), Token::Text("x".to_owned())]
        );
    }
}
