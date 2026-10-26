// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::Error;

type Assignment<'a> = (&'a str, (usize, &'a str));

/// Callers pass elements that `split_top_level_bounded` already balance-checked,
/// so the scan cannot fail.
pub(super) fn split_assignment(base: usize, input: &str) -> Option<Assignment<'_>> {
    let mut scanner = TopLevelScanner::new(input);
    while let Ok(Some((offset, character))) = scanner.next_top_level() {
        if character == '=' {
            let value = offset.saturating_add(1);
            return Some((
                &input[..offset],
                (base.saturating_add(value), &input[value..]),
            ));
        }
    }
    None
}

pub(super) fn split_top_level_bounded(
    base: usize,
    input: &str,
    delimiter: char,
    maximum_parts: Option<usize>,
) -> Result<Vec<(usize, &str)>, Error> {
    let mut result = Vec::new();
    let mut start = 0usize;
    let mut scanner = TopLevelScanner::new(input);
    while let Some((offset, character)) = match scanner.next_top_level() {
        Ok(next) => next,
        Err(ScanFailure::Unbalanced { offset, character }) => {
            return Err(Error::Syntax {
                offset: base.saturating_add(offset),
                message: format!("unexpected '{character}'"),
            });
        }
        Err(ScanFailure::Unterminated) => {
            return Err(Error::Syntax {
                offset: base.saturating_add(input.len()),
                message: "unterminated quote or delimiter".to_owned(),
            });
        }
    } {
        if character != delimiter {
            continue;
        }
        if let Some(maximum) =
            maximum_parts.filter(|maximum| result.len() >= maximum.saturating_sub(1))
        {
            return Err(Error::LayerLimit { limit: maximum });
        }
        result.push((base.saturating_add(start), &input[start..offset]));
        start = offset.saturating_add(character.len_utf8());
    }
    if let Some(maximum) = maximum_parts.filter(|maximum| result.len() >= *maximum) {
        return Err(Error::LayerLimit { limit: maximum });
    }
    result.push((base.saturating_add(start), &input[start..]));
    Ok(result)
}

pub(super) fn trim_at(base: usize, text: &str) -> (usize, &str) {
    let trimmed = text.trim_start();
    let leading = text.len().saturating_sub(trimmed.len());
    (base.saturating_add(leading), trimmed.trim_end())
}

enum QuoteState {
    Unquoted,
    Quoted,
    Escaped,
}

struct TopLevelScanner<'a> {
    chars: std::str::CharIndices<'a>,
    quote_state: QuoteState,
    delimiters: Vec<char>,
}

impl<'a> TopLevelScanner<'a> {
    fn new(input: &'a str) -> Self {
        Self {
            chars: input.char_indices(),
            quote_state: QuoteState::Unquoted,
            delimiters: Vec::new(),
        }
    }

    fn next_top_level(&mut self) -> Result<Option<(usize, char)>, ScanFailure> {
        for (offset, character) in self.chars.by_ref() {
            match self.quote_state {
                QuoteState::Unquoted => {
                    if character == '"' {
                        self.quote_state = QuoteState::Quoted;
                        continue;
                    }
                }
                QuoteState::Quoted => {
                    self.quote_state = match character {
                        '\\' => QuoteState::Escaped,
                        '"' => QuoteState::Unquoted,
                        _ => QuoteState::Quoted,
                    };
                    continue;
                }
                QuoteState::Escaped => {
                    self.quote_state = QuoteState::Quoted;
                    continue;
                }
            }
            let unbalanced = |character| ScanFailure::Unbalanced { offset, character };
            match character {
                '{' | '(' | '[' => self.delimiters.push(character),
                '}' | ')' | ']' => {
                    let expected = match character {
                        '}' => '{',
                        ')' => '(',
                        _ => '[',
                    };
                    if self.delimiters.pop() != Some(expected) {
                        return Err(unbalanced(character));
                    }
                }
                _ if self.delimiters.is_empty() => {
                    return Ok(Some((offset, character)));
                }
                _ => {}
            }
        }
        if !self.delimiters.is_empty() {
            return Err(ScanFailure::Unterminated);
        }
        match self.quote_state {
            QuoteState::Unquoted => Ok(None),
            QuoteState::Quoted | QuoteState::Escaped => Err(ScanFailure::Unterminated),
        }
    }
}

enum ScanFailure {
    Unbalanced { offset: usize, character: char },
    Unterminated,
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn crossed_delimiters_fail_at_the_crossing_and_quotes_are_preserved() {
        for (input, offset) in [("([)]", 2), ("{[}]", 2), ("[(])", 2)] {
            assert!(
                matches!(split_top_level_bounded(0, input, ',', None), Err(Error::Syntax { offset: found, .. }) if found == offset)
            );
        }
        assert_eq!(
            split_top_level_bounded(0, r#"([{}]),"([)]",x"#, ',', None)
                .unwrap()
                .len(),
            3
        );
        assert!(split_top_level_bounded(0, r#""escaped\"([)]""#, ',', None).is_ok());
    }

    #[test]
    fn quotes_and_backslashes_preserve_top_level_parts() {
        let base = 7;
        for (input, first) in [
            (r#""a\",b",tail"#, r#""a\",b""#),
            (r#""a\\",tail"#, r#""a\\""#),
            (r#""é([)],=/{}",tail"#, r#""é([)],=/{}""#),
            (r"a\,tail", r"a\"),
            (r#"a\"b,c",tail"#, r#"a\"b,c""#),
            (r"a\(b,c),tail", r"a\(b,c)"),
        ] {
            assert_eq!(
                split_top_level_bounded(base, input, ',', Some(2)).unwrap(),
                [(base, first), (base + first.len() + 1, "tail")],
                "{input}",
            );
        }
    }

    #[test]
    fn unterminated_quotes_report_the_end_byte_offset() {
        let base = 7;
        for input in [r#""é"#, r#""é\"#, r#""é\""#] {
            assert!(
                matches!(
                    split_top_level_bounded(base, input, ',', None),
                    Err(Error::Syntax { offset, message })
                        if offset == base + input.len()
                            && message == "unterminated quote or delimiter"
                ),
                "{input}",
            );
        }
    }

    #[test]
    fn unbalanced_delimiters_report_the_byte_offset_after_quotes() {
        let base = 7;
        let prefix = r#""é\",([)]",(["#;
        let input = format!("{prefix})");
        assert!(matches!(
            split_top_level_bounded(base, &input, ',', None),
            Err(Error::Syntax { offset, message })
                if offset == base + prefix.len() && message == "unexpected ')'"
        ));
    }
}
