// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use clap::builder::styling::{AnsiColor, Style};

use crate::output::envelope::Severity;

pub(super) fn style_severity_line(severity: Severity, rest: &str) -> String {
    labelled(severity_style(severity), severity.as_str(), rest)
}

pub(super) fn style_warning_line(message: &str) -> String {
    labelled(
        severity_style(Severity::Warning),
        "warning:",
        &format!(" {message}"),
    )
}

pub(super) fn style_summary_line(value: &str) -> String {
    let style = heading_style();
    match value.find(char::is_whitespace) {
        Some(split) => labelled(style, &value[..split], &value[split..]),
        None => labelled(style, value, ""),
    }
}

pub(super) fn style_document(value: &str) -> String {
    value
        .split_inclusive('\n')
        .map(|segment| match segment.strip_suffix('\n') {
            Some(line) => style_document_line(line) + "\n",
            None => style_document_line(segment),
        })
        .collect()
}

fn style_document_line(line: &str) -> String {
    if line.starts_with("For more information") || line.starts_with("Run `packetcraftr") {
        return labelled(muted_style(), line, "");
    }
    let Some((label, rest)) = line.split_once(':') else {
        return line.to_owned();
    };
    let style = match label {
        "error" => severity_style(Severity::Error),
        "warning" => severity_style(Severity::Warning),
        label if is_heading(label) => heading_style(),
        _ => return line.to_owned(),
    };
    labelled(style, &line[..=label.len()], rest)
}

/// A column-zero label of capitalized words, such as `Usage` or `Global options`.
fn is_heading(label: &str) -> bool {
    label.starts_with(|first: char| first.is_ascii_uppercase())
        && label
            .split(' ')
            .all(|word| !word.is_empty() && word.chars().all(|letter| letter.is_ascii_alphabetic()))
}

fn labelled(style: Style, label: &str, rest: &str) -> String {
    format!("{style}{label}{style:#}{rest}")
}

pub(super) fn severity_style(severity: Severity) -> Style {
    let color = match severity {
        Severity::Info => AnsiColor::Blue,
        Severity::Warning => AnsiColor::Yellow,
        Severity::Error => AnsiColor::Red,
    };
    Style::new().fg_color(Some(color.into())).bold()
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

    fn heading(label: &str) -> String {
        labelled(heading_style(), label, "")
    }

    #[test]
    fn column_zero_labels_are_headings_without_a_list_of_known_names() {
        assert_eq!(
            style_document("Usage: tool [OPTIONS]\nReserved fields:\n"),
            format!(
                "{} tool [OPTIONS]\n{}\n",
                heading("Usage:"),
                heading("Reserved fields:")
            )
        );
    }

    #[test]
    fn indented_and_lowercase_labels_stay_plain() {
        let document = "  key: value\nnote: plain\nHTTP/2: plain\nTrailing :\n no newline";
        assert_eq!(style_document(document), document);
    }

    #[test]
    fn clap_error_prefixes_take_their_severity_colour() {
        assert_eq!(
            style_document("error: bad\nwarning: odd"),
            format!(
                "{} bad\n{} odd",
                labelled(severity_style(Severity::Error), "error:", ""),
                labelled(severity_style(Severity::Warning), "warning:", "")
            )
        );
    }
}
