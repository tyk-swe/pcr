// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

// Shared capture-file and terminal rendering.

use std::io::{self, Write};

use anstyle::{AnsiColor, Style};
use packetcraftr::{
    capture::{Format, Frame, LinkType, Writer},
    output,
};
use serde::Serialize;

use super::errors::CliError;

#[derive(Clone, Copy, Debug)]
struct CaptureInterfaceMapping {
    link_type: LinkType,
    output_id: u32,
}

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

pub(super) fn capture_file_frame(mut frame: Frame, format: Format) -> Frame {
    match format {
        Format::Pcap => frame.interface = None,
        Format::PcapNg => frame.interface = Some(0),
    }
    frame
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
    if format == Format::Pcap {
        let mut writer = Writer::new(Vec::new(), format, first.link_type).map_err(|source| {
            CliError::new(5, format!("initialize capture output failed: {source}"))
        })?;
        writer
            .write_frame(&capture_file_frame(first, format))
            .map_err(|source| CliError::new(5, format!("write capture output failed: {source}")))?;
        for frame in frames {
            writer
                .write_frame(&capture_file_frame(frame, format))
                .map_err(|source| {
                    CliError::new(5, format!("write capture output failed: {source}"))
                })?;
        }
        return Ok(writer.into_inner());
    }

    let mut writer = Writer::pcapng(Vec::new()).map_err(|source| {
        CliError::new(5, format!("initialize capture output failed: {source}"))
    })?;
    let mut interfaces = Vec::<CaptureInterfaceMapping>::new();
    for mut frame in std::iter::once(first).chain(frames) {
        let interface = match interfaces
            .iter()
            .find(|mapping| mapping.link_type == frame.link_type)
        {
            Some(mapping) => mapping.output_id,
            None => {
                let interface = writer.add_interface(frame.link_type).map_err(|source| {
                    CliError::new(5, format!("initialize capture interface failed: {source}"))
                })?;
                interfaces.push(CaptureInterfaceMapping {
                    link_type: frame.link_type,
                    output_id: interface,
                });
                interface
            }
        };
        frame.interface = Some(interface);
        writer
            .write_frame(&frame)
            .map_err(|source| CliError::new(5, format!("write capture output failed: {source}")))?;
    }
    Ok(writer.into_inner())
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
