// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

// Shared capture-file and terminal rendering.

use std::io::{self, Write};

use packetcraftr::{
    capture::{Format, Frame, LinkType, Writer},
    output,
    packet::diagnostic::Diagnostic,
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

pub(super) struct NdjsonStream<W: Write> {
    writer: io::BufWriter<W>,
    command: output::contract::Command,
    next_sequence: u64,
}

impl<W: Write> NdjsonStream<W> {
    pub(super) fn new(writer: W, command: output::contract::Command) -> Self {
        Self {
            writer: io::BufWriter::new(writer),
            command,
            next_sequence: 0,
        }
    }

    pub(super) fn emit<T: Serialize>(
        &mut self,
        event: T,
        diagnostics: Vec<Diagnostic>,
    ) -> Result<(), CliError> {
        let record =
            output::envelope::Stream::success(self.command, self.next_sequence, event, diagnostics);
        self.write_record(&record)
    }

    pub(super) fn emit_terminal<T: Serialize>(
        &mut self,
        event: T,
        diagnostics: Vec<Diagnostic>,
        stats: output::envelope::Stats,
    ) -> Result<(), CliError> {
        let record =
            output::envelope::Stream::success(self.command, self.next_sequence, event, diagnostics)
                .with_stats(stats);
        self.write_record(&record)
    }

    pub(super) const fn next_sequence(&self) -> u64 {
        self.next_sequence
    }

    fn write_record(&mut self, record: &impl Serialize) -> Result<(), CliError> {
        let sequence = self.next_sequence;
        let following = sequence.checked_add(1).ok_or_else(|| {
            CliError::classified(output::contract::Error::SequenceOverflow).at_sequence(sequence)
        })?;
        serde_json::to_writer(&mut self.writer, record).map_err(|source| {
            let exit_code = if source.is_io() { 5 } else { 70 };
            CliError::new(exit_code, format!("serialize output failed: {source}"))
                .at_sequence(sequence)
        })?;
        self.writer
            .write_all(b"\n")
            .and_then(|()| self.writer.flush())
            .map_err(|source| {
                CliError::new(5, format!("write stdout failed: {source}")).at_sequence(sequence)
            })?;
        self.next_sequence = following;
        Ok(())
    }
}

pub(super) fn write_stdout_line(arguments: std::fmt::Arguments<'_>) -> Result<(), CliError> {
    let rendered = terminal_safe(&arguments.to_string());
    write_machine_line(&rendered)
}

fn write_machine_line(rendered: &str) -> Result<(), CliError> {
    let mut stdout = io::stdout().lock();
    stdout
        .write_all(rendered.as_bytes())
        .and_then(|()| stdout.write_all(b"\n"))
        .and_then(|()| stdout.flush())
        .map_err(|source| CliError::new(5, format!("write stdout failed: {source}")))
}

pub(super) fn emit_stderr_error(message: &str) -> Result<(), CliError> {
    let mut stderr = io::stderr().lock();
    writeln!(stderr, "error: {}", terminal_safe(message))
        .and_then(|()| stderr.flush())
        .map_err(|source| CliError::new(5, format!("write stderr failed: {source}")))
}

pub(super) fn emit_stderr_message(message: &str) -> Result<(), CliError> {
    let mut stderr = io::stderr().lock();
    writeln!(stderr, "{}", terminal_safe(message))
        .and_then(|()| stderr.flush())
        .map_err(|source| CliError::new(5, format!("write stderr failed: {source}")))
}

pub(super) fn terminal_safe(value: &str) -> String {
    let mut safe = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
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
