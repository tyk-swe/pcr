// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

pub(crate) fn terminal_document(value: &str) -> String {
    terminal_safe_document(&anstream::adapter::strip_str(value).to_string())
}

/// Escaped so captured header bytes can neither drive the terminal nor forge another line.
pub(crate) fn escaped(value: &str) -> String {
    value.chars().flat_map(char::escape_default).collect()
}

pub(crate) fn terminal_safe(value: &str) -> String {
    sanitized(value, Newlines::Escaped)
}

fn terminal_safe_document(value: &str) -> String {
    sanitized(value, Newlines::Kept)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Newlines {
    Escaped,
    Kept,
}

fn sanitized(value: &str, newlines: Newlines) -> String {
    let preserve_newlines = newlines == Newlines::Kept;
    let mut safe = String::with_capacity(value.len());
    let mut characters = value.chars().peekable();
    while let Some(character) = characters.next() {
        match character {
            '\n' if preserve_newlines => safe.push('\n'),
            '\r' if preserve_newlines && characters.peek() == Some(&'\n') => {
                characters.next();
                safe.push('\n');
            }
            '\n' => safe.push_str("\\n"),
            '\r' => safe.push_str("\\r"),
            '\t' => safe.push_str("\\t"),
            character
                if character.is_control()
                    || matches!(
                        character,
                        '\u{061c}'
                            | '\u{200b}'..='\u{200f}'
                            | '\u{2028}'..='\u{202e}'
                            | '\u{2060}'..='\u{206f}'
                            | '\u{feff}'
                    ) =>
            {
                use std::fmt::Write as _;
                let _ = write!(safe, "\\u{{{:x}}}", u32::from(character));
            }
            character => safe.push(character),
        }
    }
    safe
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lines_escape_everything_that_could_move_the_cursor_or_forge_a_line() {
        assert_eq!(
            terminal_safe("a\nb\rc\td\u{1b}[31m\u{202e}e"),
            "a\\nb\\rc\\td\\u{1b}[31m\\u{202e}e"
        );
    }

    #[test]
    fn documents_keep_their_line_breaks_and_lose_styling_and_controls() {
        assert_eq!(
            terminal_document("Usage:\r\n  \u{1b}[1mtool\u{1b}[0m\n\rend\u{202e}"),
            "Usage:\n  tool\n\\rend\\u{202e}"
        );
    }

    #[test]
    fn escaped_header_bytes_stay_on_one_line() {
        assert_eq!(escaped("a\r\nb\u{1b}"), "a\\r\\nb\\u{1b}");
    }
}
