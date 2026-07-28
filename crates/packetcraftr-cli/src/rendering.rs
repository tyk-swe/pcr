// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

// Shared capture-file and terminal rendering.

use std::io::{self, Write};

use anstyle::{AnsiColor, Style};
use packetcraftr::{
    capture::{Format, Frame, Writer},
    output, packet,
};
use serde::Serialize;

use super::capture_output::CaptureOutput;
use super::errors::CliError;

pub(super) fn capture_file_format(output: output::contract::Format) -> Result<Format, CliError> {
    match output {
        output::contract::Format::Pcap => Ok(Format::Pcap),
        output::contract::Format::Pcapng => Ok(Format::PcapNg),
        _ => Err(CliError::new(
            70,
            "capture-file renderer received a non-capture format",
        )),
    }
}

pub(super) fn write_capture_file(
    output: output::contract::Format,
    frames: impl IntoIterator<Item = Frame>,
) -> Result<(), CliError> {
    write_raw(&encode_capture_file(output, frames)?)
}

pub(super) fn encode_capture_file(
    output: output::contract::Format,
    frames: impl IntoIterator<Item = Frame>,
) -> Result<Vec<u8>, CliError> {
    let format = capture_file_format(output)?;
    let mut frames = frames.into_iter();
    let first = frames.next().ok_or_else(|| {
        CliError::new(
            2,
            "capture-file output requires at least one captured or transmitted frame",
        )
    })?;
    let writer = match format {
        Format::Pcap => Writer::new(Vec::new(), format, first.link_type),
        Format::PcapNg => Writer::pcapng(Vec::new()),
    }
    .map_err(|source| CliError::new(5, format!("initialize capture output failed: {source}")))?;
    let mut output = CaptureOutput::link_mapped(writer);
    for mut frame in std::iter::once(first).chain(frames) {
        output.add_link_type(frame.link_type).map_err(|source| {
            CliError::new(5, format!("initialize capture interface failed: {source}"))
        })?;
        // Classic PCAP cannot carry an interface ID; PCAPNG uses the
        // lifecycle's stable per-link-type mapping.
        if format == Format::Pcap {
            frame.interface = None;
        }
        output
            .write_link_mapped(frame)
            .map_err(|source| CliError::new(5, format!("write capture output failed: {source}")))?;
    }
    Ok(output.into_inner())
}

pub(super) fn spaced_hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len().saturating_mul(3));
    for (index, byte) in bytes.iter().enumerate() {
        use std::fmt::Write as _;
        if index != 0 {
            output.push(' ');
        }
        let _ = write!(output, "{byte:02x}");
    }
    output
}

pub(super) fn output_timestamp_text(timestamp: output::frame::Timestamp) -> String {
    if timestamp.unix_seconds >= 0 || timestamp.nanoseconds == 0 {
        return format!("{}.{:09}", timestamp.unix_seconds, timestamp.nanoseconds);
    }

    // OutputTimestamp uses the canonical floor-seconds representation, so
    // (-3, 750_000_000) is -2.25 seconds rather than -3.75 seconds. Convert
    // that pair to conventional signed decimal notation for human output.
    let whole_seconds = -(timestamp.unix_seconds + 1);
    let fractional = 1_000_000_000 - timestamp.nanoseconds;
    format!("-{whole_seconds}.{fractional:09}")
}

pub(super) fn emit_json(value: &impl Serialize) -> Result<(), CliError> {
    let rendered = serde_json::to_string_pretty(value)
        .map_err(|source| CliError::new(70, format!("serialize output failed: {source}")))?;
    write_machine_line(&rendered)
}

pub(super) fn emit_json_compact(value: &impl Serialize) -> Result<(), CliError> {
    let rendered = serde_json::to_string(value)
        .map_err(|source| CliError::new(70, format!("serialize output failed: {source}")))?;
    write_machine_line(&rendered)
}

pub(super) fn emit_stream_record<T: Serialize>(
    command: output::contract::Command,
    sequence: &mut u64,
    result: T,
) -> Result<(), CliError> {
    emit_json_compact(&output::envelope::Stream::success(
        command,
        *sequence,
        result,
        Vec::new(),
    ))
    .map_err(|error| error.at_sequence(*sequence))?;
    *sequence = sequence.checked_add(1).ok_or_else(|| {
        CliError::classified(output::contract::Error::SequenceOverflow).at_sequence(*sequence)
    })?;
    Ok(())
}

pub(super) fn render_diagnostics_text(
    diagnostics: &[packet::diagnostic::Diagnostic],
) -> Result<(), CliError> {
    for diagnostic in diagnostics {
        write_stdout_line(format_args!(
            "{:?} {}: {}",
            diagnostic.severity, diagnostic.code, diagnostic.message
        ))?;
    }
    Ok(())
}

pub(super) fn render_output_diagnostics_text(
    diagnostics: &[output::envelope::Diagnostic],
) -> Result<(), CliError> {
    for diagnostic in diagnostics {
        write_stdout_line(format_args!(
            "{:?} {}: {}",
            diagnostic.severity, diagnostic.code, diagnostic.message
        ))?;
    }
    Ok(())
}

pub(super) fn write_stdout_line(arguments: std::fmt::Arguments<'_>) -> Result<(), CliError> {
    let rendered = style_human_line(&terminal_safe(&arguments.to_string()));
    write_human_stdout(&rendered, true)
}

pub(super) fn write_plain_line(arguments: std::fmt::Arguments<'_>) -> Result<(), CliError> {
    write_machine_line(&terminal_safe(&arguments.to_string()))
}

fn write_machine_line(rendered: &str) -> Result<(), CliError> {
    let mut stdout = io::stdout().lock();
    write_terminated(&mut stdout, rendered, true)
        .map_err(|source| CliError::new(5, format!("write stdout failed: {source}")))
}

pub(super) fn terminal_document(value: &str) -> String {
    terminal_safe_document(&anstream::adapter::strip_str(value).to_string())
}

pub(super) fn emit_stdout_document(message: &str) -> Result<(), CliError> {
    let rendered = style_document(&terminal_document(message));
    write_human_stdout(&rendered, false)
}

pub(super) fn emit_stderr_document(message: &str) -> Result<(), CliError> {
    let rendered = style_document(&terminal_document(message));
    write_human_stderr(&rendered, false)
}

pub(super) fn emit_stderr_error(message: &str) -> Result<(), CliError> {
    let style = error_style();
    let rendered = format!("{style}error:{style:#} {}", terminal_safe(message));
    write_human_stderr(&rendered, true)
}

pub(super) fn emit_stderr_message(message: &str) -> Result<(), CliError> {
    let rendered = style_human_line(&terminal_safe(message));
    write_human_stderr(&rendered, true)
}

fn write_human_stdout(rendered: &str, append_newline: bool) -> Result<(), CliError> {
    let stdout = anstream::stdout();
    let mut stdout = stdout.lock();
    write_terminated(&mut stdout, rendered, append_newline)
        .map_err(|source| CliError::new(5, format!("write stdout failed: {source}")))
}

fn write_human_stderr(rendered: &str, append_newline: bool) -> Result<(), CliError> {
    let stderr = anstream::stderr();
    let mut stderr = stderr.lock();
    write_terminated(&mut stderr, rendered, append_newline)
        .map_err(|source| CliError::new(5, format!("write stderr failed: {source}")))
}

fn write_terminated(
    writer: &mut impl Write,
    rendered: &str,
    append_newline: bool,
) -> io::Result<()> {
    writer.write_all(rendered.as_bytes())?;
    if append_newline || !rendered.ends_with('\n') {
        writer.write_all(b"\n")?;
    }
    writer.flush()
}

fn style_human_line(value: &str) -> String {
    const SUCCESSES: &[&str] = &[
        "built",
        "captured",
        "completed",
        "decoded",
        "generated",
        "planned",
        "read",
        "replayed",
        "scanned",
        "sent",
    ];

    if let Some((prefix, rest)) = split_leading_token(value) {
        let style = match prefix {
            "Error" | "ERROR" => Some(error_style()),
            "Warning" | "WARNING" => Some(warning_style()),
            "Info" | "INFO" | "Note" | "NOTE" => Some(info_style()),
            _ if SUCCESSES.contains(&prefix) => Some(success_style()),
            _ => None,
        };
        if let Some(style) = style {
            return format!("{style}{prefix}{style:#}{}", style_key_value_labels(rest));
        }
    }

    if let Some(rest) = value.strip_prefix("error:") {
        let style = error_style();
        return format!("{style}error:{style:#}{}", style_key_value_labels(rest));
    }
    if let Some(rest) = value.strip_prefix("warning:") {
        let style = warning_style();
        return format!("{style}warning:{style:#}{}", style_key_value_labels(rest));
    }
    style_key_value_labels(value)
}

fn split_leading_token(value: &str) -> Option<(&str, &str)> {
    let split = value.find(|character: char| character.is_whitespace())?;
    Some((&value[..split], &value[split..]))
}

fn style_key_value_labels(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut rendered = String::with_capacity(value.len());
    let mut copied = 0;
    let mut index = 0;
    while index < bytes.len() {
        let starts_key = bytes[index].is_ascii_alphabetic() || bytes[index] == b'_';
        let boundary =
            index == 0 || matches!(bytes[index - 1], b' ' | b',' | b'(' | b'[' | b'{' | b':');
        if starts_key && boundary {
            let mut end = index + 1;
            while end < bytes.len()
                && (bytes[end].is_ascii_alphanumeric() || matches!(bytes[end], b'_' | b'-' | b'.'))
            {
                end += 1;
            }
            if bytes.get(end) == Some(&b'=') {
                rendered.push_str(&value[copied..index]);
                let style = key_style();
                rendered.push_str(&format!("{style}{}{style:#}", &value[index..end]));
                rendered.push('=');
                copied = end + 1;
                index = copied;
                continue;
            }
        }
        let character = value[index..]
            .chars()
            .next()
            .expect("index remains on a UTF-8 boundary");
        index += character.len_utf8();
    }
    rendered.push_str(&value[copied..]);
    rendered
}

fn style_document(value: &str) -> String {
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

fn error_style() -> Style {
    Style::new().fg_color(Some(AnsiColor::Red.into())).bold()
}

fn warning_style() -> Style {
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

fn key_style() -> Style {
    Style::new().fg_color(Some(AnsiColor::Cyan.into()))
}

fn muted_style() -> Style {
    Style::new().dimmed()
}

pub(super) fn terminal_safe(value: &str) -> String {
    terminal_safe_with_layout(value, false)
}

pub(super) fn terminal_safe_document(value: &str) -> String {
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

pub(super) fn write_raw(bytes: &[u8]) -> Result<(), CliError> {
    let mut stdout = io::stdout().lock();
    stdout
        .write_all(bytes)
        .and_then(|()| stdout.flush())
        .map_err(|source| CliError::new(5, format!("write stdout failed: {source}")))
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, SystemTime};

    use packetcraftr::{
        capture::{Frame, LinkType, Reader},
        output,
    };

    use super::{
        encode_capture_file, output_timestamp_text, terminal_document, terminal_safe,
        terminal_safe_document,
    };

    #[test]
    fn whole_frame_hex_is_not_truncated() {
        let bytes = (0u8..=255).collect::<Vec<_>>();
        assert_eq!(output::frame::Wire::new(bytes).bytes_hex.len(), 512);
    }

    #[test]
    fn terminal_text_escapes_controls_and_directional_overrides() {
        let safe = terminal_safe("line\n\u{1b}[31m\u{2028}next\u{2029}\u{202e}tail");
        assert_eq!(
            safe,
            "line\\n\\u{1b}[31m\\u{2028}next\\u{2029}\\u{202e}tail"
        );
        assert!(!safe.chars().any(char::is_control));
        assert!(!safe.contains(['\u{2028}', '\u{2029}']));
    }

    #[test]
    fn terminal_documents_preserve_layout_but_escape_terminal_controls() {
        let safe = terminal_safe_document("first\r\nsecond\n\t\u{1b}[31m\u{202e}tail");
        assert_eq!(safe, "first\nsecond\n\\t\\u{1b}[31m\\u{202e}tail");
        assert_eq!(safe.lines().count(), 3);
        assert!(!safe.contains('\u{1b}'));
        assert!(!safe.contains('\u{202e}'));

        let cleaned = terminal_document("\u{1b}[31merror:\u{1b}[0m bad\nnext");
        assert_eq!(cleaned, "error: bad\nnext");
    }

    #[test]
    fn pre_epoch_timestamp_text_uses_conventional_signed_decimal_notation() {
        assert_eq!(
            output_timestamp_text(output::frame::Timestamp {
                unix_seconds: -3,
                nanoseconds: 750_000_000,
            }),
            "-2.250000000"
        );
        assert_eq!(
            output_timestamp_text(output::frame::Timestamp {
                unix_seconds: -1,
                nanoseconds: 500_000_000,
            }),
            "-0.500000000"
        );
    }

    #[test]
    fn pcapng_exchange_evidence_preserves_multiple_link_types() {
        let raw = Frame::new(SystemTime::UNIX_EPOCH, LinkType::RAW, vec![0x45, 0, 0, 0]).unwrap();
        let ethernet = Frame::new(
            SystemTime::UNIX_EPOCH + Duration::from_nanos(1),
            LinkType::ETHERNET,
            vec![0; 14],
        )
        .unwrap();
        let bytes = encode_capture_file(
            output::contract::Format::Pcapng,
            [raw.clone(), ethernet.clone()],
        )
        .unwrap();
        let mut reader = Reader::new(std::io::Cursor::new(bytes)).unwrap();
        let decoded_raw = reader.next_frame().unwrap().unwrap();
        let decoded_ethernet = reader.next_frame().unwrap().unwrap();

        assert_eq!(decoded_raw.link_type, raw.link_type);
        assert_eq!(decoded_raw.bytes(), raw.bytes());
        assert_eq!(decoded_raw.interface, Some(0));
        assert_eq!(decoded_ethernet.link_type, ethernet.link_type);
        assert_eq!(decoded_ethernet.bytes(), ethernet.bytes());
        assert_eq!(decoded_ethernet.interface, Some(1));
        assert!(reader.next_frame().unwrap().is_none());

        let error =
            encode_capture_file(output::contract::Format::Pcap, [raw, ethernet]).unwrap_err();
        assert_eq!(error.exit_code, 5);
        assert!(error.message.contains("link type"));
    }
}
