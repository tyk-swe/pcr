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
    paren_depth: usize,
    list_depth: usize,
    object_depth: usize,
}

impl<'a> TopLevelScanner<'a> {
    fn new(input: &'a str) -> Self {
        Self {
            chars: input.char_indices(),
            quoted: false,
            escaped: false,
            paren_depth: 0,
            list_depth: 0,
            object_depth: 0,
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
                '{' => self.object_depth = self.object_depth.saturating_add(1),
                '}' => {
                    self.object_depth = self
                        .object_depth
                        .checked_sub(1)
                        .ok_or_else(|| unbalanced(character))?;
                }
                '(' => self.paren_depth = self.paren_depth.saturating_add(1),
                ')' => {
                    let Some(depth) = self.paren_depth.checked_sub(1) else {
                        return Err(unbalanced(character));
                    };
                    self.paren_depth = depth;
                }
                '[' => self.list_depth = self.list_depth.saturating_add(1),
                ']' => {
                    let Some(depth) = self.list_depth.checked_sub(1) else {
                        return Err(unbalanced(character));
                    };
                    self.list_depth = depth;
                }
                _ if self.paren_depth == 0 && self.list_depth == 0 && self.object_depth == 0 => {
                    return Ok(Some((offset, character)));
                }
                _ => {}
            }
        }
        if self.quoted || self.paren_depth != 0 || self.list_depth != 0 || self.object_depth != 0 {
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
