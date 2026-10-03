// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use clap::builder::styling::{AnsiColor, Style};

pub(crate) fn terminal_document(value: &str) -> String {
    terminal_safe_document(&anstream::adapter::strip_str(value).to_string())
}

pub(crate) fn terminal_safe(value: &str) -> String {
    terminal_safe_with_layout(value, false)
}

pub(crate) fn terminal_safe_document(value: &str) -> String {
    terminal_safe_with_layout(value, true)
}

fn terminal_safe_with_layout(value: &str, preserve_newlines: bool) -> String {
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

pub(crate) fn style_human_line(value: &str) -> String {
    if let Some((prefix, rest)) = split_leading_token(value) {
        let style = match prefix {
            "error" => Some(error_style()),
            "warning" => Some(warning_style()),
            "info" => Some(info_style()),
            _ => None,
        };
        if let Some(style) = style {
            return format!("{style}{prefix}{style:#}{rest}");
        }
    }

    if let Some(rest) = value.strip_prefix("error:") {
        let style = error_style();
        return format!("{style}error:{style:#}{rest}");
    }
    if let Some(rest) = value.strip_prefix("warning:") {
        let style = warning_style();
        return format!("{style}warning:{style:#}{rest}");
    }
    value.to_owned()
}

pub(crate) fn style_summary_line(value: &str) -> String {
    let style = success_style();
    match split_leading_token(value) {
        Some((prefix, rest)) => format!("{style}{prefix}{style:#}{rest}"),
        None => format!("{style}{value}{style:#}"),
    }
}

fn split_leading_token(value: &str) -> Option<(&str, &str)> {
    let split = value.find(|character: char| character.is_whitespace())?;
    Some((&value[..split], &value[split..]))
}

pub(crate) fn style_document(value: &str) -> String {
    let mut rendered = String::with_capacity(value.len());
    for segment in value.split_inclusive('\n') {
        let (line, newline) = match segment.strip_suffix('\n') {
            Some(line) => (line, "\n"),
            None => (segment, ""),
        };
        rendered.push_str(&style_document_line(line));
        rendered.push_str(newline);
    }
    rendered
}

fn style_document_line(line: &str) -> String {
    for (prefix, style) in [
        ("error:", error_style()),
        ("warning:", warning_style()),
        ("Usage:", heading_style()),
        ("Commands:", heading_style()),
        ("Arguments:", heading_style()),
        ("Options:", heading_style()),
        ("Global options:", heading_style()),
        ("Output formats:", heading_style()),
        ("Examples:", heading_style()),
        ("Example:", heading_style()),
        ("Notes:", heading_style()),
    ] {
        if let Some(rest) = line.strip_prefix(prefix) {
            return format!("{style}{prefix}{style:#}{rest}");
        }
    }
    if line.starts_with("For more information") || line.starts_with("Run `packetcraftr") {
        let style = muted_style();
        return format!("{style}{line}{style:#}");
    }
    line.to_owned()
}

pub(crate) fn error_style() -> Style {
    Style::new().fg_color(Some(AnsiColor::Red.into())).bold()
}

pub(crate) fn warning_style() -> Style {
    Style::new().fg_color(Some(AnsiColor::Yellow.into())).bold()
}

fn success_style() -> Style {
    Style::new().fg_color(Some(AnsiColor::Green.into())).bold()
}

fn info_style() -> Style {
    Style::new().fg_color(Some(AnsiColor::Blue.into())).bold()
}

fn heading_style() -> Style {
    Style::new().fg_color(Some(AnsiColor::Cyan.into())).bold()
}

fn muted_style() -> Style {
    Style::new().dimmed()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn terminal_documents_strip_ansi_before_preserving_layout() {
        assert_eq!(
            terminal_document("\u{1b}[31merror:\u{1b}[0m\n\tvalue"),
            "error:\n\\tvalue",
        );
    }
}
