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

struct TopLevelScanner<'a> {
    chars: std::str::CharIndices<'a>,
    quoted: bool,
    escaped: bool,
    delimiters: Vec<char>,
}

impl<'a> TopLevelScanner<'a> {
    fn new(input: &'a str) -> Self {
        Self {
            chars: input.char_indices(),
            quoted: false,
            escaped: false,
            delimiters: Vec::new(),
        }
    }

    fn next_top_level(&mut self) -> Result<Option<(usize, char)>, ScanFailure> {
        for (offset, character) in self.chars.by_ref() {
            if self.escaped {
                self.escaped = false;
                continue;
            }
            if self.quoted && character == '\\' {
                self.escaped = true;
                continue;
            }
            if character == '"' {
                self.quoted = !self.quoted;
                continue;
            }
            if self.quoted {
                continue;
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
        if self.quoted || !self.delimiters.is_empty() {
            Err(ScanFailure::Unterminated)
        } else {
            Ok(None)
        }
    }
}

enum ScanFailure {
    Unbalanced { offset: usize, character: char },
    Unterminated,
}

#[cfg(test)]
mod improvement_tests {
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
}
