// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

// Shared capture-file and terminal rendering.

#[derive(Clone, Copy, Debug)]
struct CaptureInterfaceMapping {
    link_type: LinkType,
    output_id: u32,
}

fn capture_file_format(output: OutputFormat) -> Result<Format, CliError> {
    match output {
        OutputFormat::Pcap => Ok(Format::Pcap),
        OutputFormat::Pcapng => Ok(Format::PcapNg),
        _ => Err(CliError::new(
            70,
            "capture-file renderer received a non-capture format",
        )),
    }
}

fn capture_file_frame(mut frame: Frame, format: Format) -> Frame {
    match format {
        Format::Pcap => frame.interface = None,
        Format::PcapNg => frame.interface = Some(0),
    }
    frame
}

fn write_capture_file(
    output: OutputFormat,
    frames: impl IntoIterator<Item = Frame>,
) -> Result<(), CliError> {
    write_raw(&encode_capture_file(output, frames)?)
}

fn encode_capture_file(
    output: OutputFormat,
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

fn spaced_hex(bytes: &[u8]) -> String {
    const HUMAN_PREVIEW_BYTES: usize = 128;
    let preview = &bytes[..bytes.len().min(HUMAN_PREVIEW_BYTES)];
    let mut output = String::with_capacity(preview.len().saturating_mul(3).saturating_add(32));
    for (index, byte) in preview.iter().enumerate() {
        use std::fmt::Write as _;
        if index != 0 {
            output.push(' ');
        }
        let _ = write!(output, "{byte:02x}");
    }
    if bytes.len() > preview.len() {
        output.push_str(" …");
    }
    use std::fmt::Write as _;
    let _ = write!(output, " ({} bytes)", bytes.len());
    output
}

fn output_timestamp_text(timestamp: crate::output::OutputTimestamp) -> String {
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

fn emit_json(value: &impl Serialize) -> Result<(), CliError> {
    let mut stdout = io::stdout().lock();
    serde_json::to_writer_pretty(&mut stdout, value).map_err(json_output_error)?;
    stdout
        .write_all(b"\n")
        .and_then(|()| stdout.flush())
        .map_err(|source| CliError::new(5, format!("write stdout failed: {source}")))
}

fn emit_json_compact(value: &impl Serialize) -> Result<(), CliError> {
    let mut stdout = io::stdout().lock();
    serde_json::to_writer(&mut stdout, value).map_err(json_output_error)?;
    stdout
        .write_all(b"\n")
        .and_then(|()| stdout.flush())
        .map_err(|source| CliError::new(5, format!("write stdout failed: {source}")))
}

fn json_output_error(source: serde_json::Error) -> CliError {
    if source.is_io() {
        CliError::new(5, format!("write stdout failed: {source}"))
    } else {
        CliError::new(70, format!("serialize output failed: {source}"))
    }
}

fn write_stdout_line(arguments: std::fmt::Arguments<'_>) -> Result<(), CliError> {
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

fn emit_stderr_error(message: &str) -> Result<(), CliError> {
    let mut stderr = io::stderr().lock();
    writeln!(stderr, "error: {}", terminal_safe(message))
        .and_then(|()| stderr.flush())
        .map_err(|source| CliError::new(5, format!("write stderr failed: {source}")))
}

fn emit_stderr_message(message: &str) -> Result<(), CliError> {
    let mut stderr = io::stderr().lock();
    writeln!(stderr, "{}", terminal_safe(message))
        .and_then(|()| stderr.flush())
        .map_err(|source| CliError::new(5, format!("write stderr failed: {source}")))
}

fn terminal_safe(value: &str) -> String {
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

fn write_raw(bytes: &[u8]) -> Result<(), CliError> {
    let mut stdout = io::stdout().lock();
    stdout
        .write_all(bytes)
        .and_then(|()| stdout.flush())
        .map_err(|source| CliError::new(5, format!("write stdout failed: {source}")))
}
