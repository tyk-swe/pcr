// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

// Offline build, dissect, and capture-read commands.

use std::fs::File;
use std::io;
use std::time::SystemTime;

use packetcraftr::{
    capture::{
        self, Format as CaptureFormat, Frame, Limits, LinkType, Reader, ReaderOptions, Writer,
        transcode,
    },
    error::{Classification, Kind},
    output, packet,
};

use super::super::arguments::{BuildArgs, CliBuildMode, DissectArgs, ReadArgs};
use super::super::errors::CliError;
use super::super::filtering::{self, Capabilities};
use super::super::input::{read_bounded_file, read_recipe, read_stdin_bounded};
use super::super::rendering::{
    capture_file_format, emit_json, emit_json_compact, spaced_hex, write_plain_line, write_raw,
    write_stdout_line,
};
use super::super::runtime::default_registry_arc;

pub(crate) fn run_build(
    arguments: BuildArgs,
    output: output::contract::Format,
) -> Result<(), CliError> {
    let registry = default_registry_arc()?;
    let packet = read_recipe(arguments.recipe, &registry)?;
    let built = packet::build::Builder::new(registry)
        .build(
            packet,
            packet::build::Context::default(),
            packet::build::Options {
                mode: match arguments.mode {
                    CliBuildMode::Strict => packet::build::Mode::Strict,
                    CliBuildMode::Permissive => packet::build::Mode::Permissive,
                },
                ..packet::build::Options::default()
            },
        )
        .map_err(|source| CliError::new(3, source.to_string()))?;
    let (result, diagnostics) = output::build::Result::from_built(built);
    match output {
        output::contract::Format::Text => {
            write_stdout_line(format_args!("built {} bytes", result.length))?;
            write_stdout_line(format_args!("{}", spaced_hex(result.bytes())))?;
            for diagnostic in &diagnostics {
                write_stdout_line(format_args!(
                    "{:?} {}: {}",
                    diagnostic.severity, diagnostic.code, diagnostic.message
                ))?;
            }
            Ok(())
        }
        output::contract::Format::Hex => write_plain_line(format_args!("{}", result.bytes_hex)),
        output::contract::Format::Raw => write_raw(result.bytes()),
        output::contract::Format::Json => emit_json(&output::envelope::Aggregate::success(
            output::contract::Command::Build,
            result,
            diagnostics,
        )),
        _ => Err(CliError::classified(
            output::contract::Error::UnsupportedFormat {
                command: output::contract::Command::Build,
                format: output,
            },
        )),
    }
}

pub(crate) fn run_dissect(
    arguments: DissectArgs,
    output: output::contract::Format,
) -> Result<(), CliError> {
    let registry = default_registry_arc()?;
    // A bad filter fails before any input is read, so it cannot leave the
    // command waiting on standard input for frame bytes it would never use.
    let filter = match arguments.filter.as_deref() {
        Some(source) => Some(filtering::compile(
            source,
            &registry,
            Capabilities::frames_only(),
        )?),
        None => None,
    };
    let bytes = match (arguments.hex, arguments.file) {
        (Some(value), None) => packet::expression::decode_hex(&value)
            .map_err(|source| CliError::new(2, source.to_string()))?
            .to_vec(),
        (None, Some(path)) => {
            read_bounded_file(&path, packet::document::DEFAULT_MAX_DOCUMENT_BYTES)?
        }
        (None, None) => read_stdin_bounded(packet::document::DEFAULT_MAX_DOCUMENT_BYTES)?,
        (Some(_), Some(_)) => unreachable!("clap enforces conflicts"),
    };
    let decoded = packet::decode::Decoder::new(registry)
        .decode(
            Frame::new(SystemTime::now(), LinkType(arguments.link_type), bytes)
                .map_err(|source| CliError::new(3, source.to_string()))?,
            packet::decode::Options::default(),
        )
        .map_err(|source| CliError::new(3, source.to_string()))?;
    // The filter selects emission, not validity: a frame it rejects emits
    // nothing and the command still succeeds, while an unsupported output
    // format is refused whether or not the frame matched.
    let kept = match &filter {
        Some(filter) => filter.matches(&packet::filter::Context {
            decoded: &decoded,
            number: 1,
            tcp_stream: None,
            udp_stream: None,
        }),
        None => true,
    };
    let (result, diagnostics) = output::dissect::Result::from_decoded(decoded);
    match output {
        output::contract::Format::Text => {
            if !kept {
                return Ok(());
            }
            write_stdout_line(format_args!(
                "decoded {} bytes into {} layer(s)",
                result.length,
                result.packet.layers.len()
            ))?;
            for (index, layer) in result.packet.layers.iter().enumerate() {
                write_stdout_line(format_args!("{index}: {}", layer.protocol))?;
            }
            for diagnostic in &diagnostics {
                write_stdout_line(format_args!(
                    "{:?} {}: {}",
                    diagnostic.severity, diagnostic.code, diagnostic.message
                ))?;
            }
            Ok(())
        }
        output::contract::Format::Hex => {
            if !kept {
                return Ok(());
            }
            write_plain_line(format_args!("{}", result.bytes_hex))
        }
        output::contract::Format::Raw => {
            if !kept {
                return Ok(());
            }
            write_raw(result.bytes())
        }
        output::contract::Format::Json => {
            if !kept {
                return Ok(());
            }
            emit_json(&output::envelope::Aggregate::success(
                output::contract::Command::Dissect,
                result,
                diagnostics,
            ))
        }
        _ => Err(CliError::classified(
            output::contract::Error::UnsupportedFormat {
                command: output::contract::Command::Dissect,
                format: output,
            },
        )),
    }
}

pub(crate) fn run_read(
    arguments: ReadArgs,
    output: output::contract::Format,
) -> Result<(), CliError> {
    let ReadArgs {
        path,
        max_frames,
        max_bytes,
        max_frame_bytes,
        max_interfaces,
        filter,
        dissect,
    } = arguments;
    validate_capture_stream_limits(max_frames, max_bytes, max_frame_bytes, max_interfaces)?;
    // Hexadecimal and capture-file output carry frame bytes and nothing else,
    // so there is nowhere to put a layer stack. Say so rather than accepting
    // the flag and quietly ignoring it.
    if dissect
        && !matches!(
            output,
            output::contract::Format::Text | output::contract::Format::Ndjson
        )
    {
        return Err(CliError::from_classification(
            Classification::new(
                "cli.dissect_unsupported_format",
                Kind::Cli,
                Some("use --output text or --output ndjson to show the layer stack"),
            ),
            format!("--dissect has no effect on {output} output"),
            Vec::new(),
        ));
    }

    // Dissection is the price of filtering, and of showing the layer stack.
    // With neither requested, reading stays exactly the copy it always was.
    let decoding = if filter.is_some() || dissect {
        let registry = default_registry_arc()?;
        let compiled = match filter.as_deref() {
            Some(source) => Some(filtering::compile(
                source,
                &registry,
                Capabilities::frames_only(),
            )?),
            None => None,
        };
        Some((packet::decode::Decoder::new(registry), compiled))
    } else {
        None
    };

    let file = File::open(&path)
        .map_err(|source| CliError::new(5, format!("open {} failed: {source}", path.display())))?;
    let mut reader = Reader::with_options(
        file,
        ReaderOptions {
            max_size: max_frame_bytes,
            max_interfaces_per_section: max_interfaces,
            ..ReaderOptions::default()
        },
    )
    .map_err(CliError::classified)?;
    let stream_limits = Limits {
        max_frames,
        max_bytes,
    };

    if matches!(
        output,
        output::contract::Format::Pcap | output::contract::Format::Pcapng
    ) {
        // Transcoding copies every record verbatim, so it cannot honour a
        // filter. Selecting frames instead writes a new capture containing
        // only the survivors, which is how a subset is extracted.
        if let Some((decoder, Some(compiled))) = &decoding {
            return write_filtered_capture(
                &mut reader,
                decoder,
                compiled,
                output,
                stream_limits,
                max_frame_bytes,
                max_interfaces,
            );
        }
        let format = capture_file_format(output)?;
        let stdout = io::stdout();
        let (_output, _report) = transcode(&mut reader, stdout.lock(), format, stream_limits)
            .map_err(CliError::classified)?;
        return Ok(());
    }

    // Two counters, because they answer different questions: `frames` is the
    // frame's position in the capture, which is what a filter reads and what
    // the byte and frame budgets account for, while `sequence` numbers the
    // records actually emitted so a filtered stream stays contiguous.
    let mut sequence = 0_u64;
    let mut frames = 0_u64;
    let mut captured_bytes = 0_u64;
    loop {
        let Some(frame) = reader
            .next_frame()
            .map_err(|source| CliError::classified(source).at_sequence(sequence))?
        else {
            return Ok(());
        };
        frames = next_frame_number(frames, sequence)?;
        if frames > max_frames {
            return Err(CliError::classified(capture::Error::FrameLimitExceeded {
                actual: frames,
                limit: max_frames,
            })
            .at_sequence(sequence));
        }
        captured_bytes = captured_bytes
            .checked_add(u64::from(frame.captured_length()))
            .ok_or_else(|| {
                CliError::classified(capture::Error::StreamByteLimitExceeded {
                    actual: u64::MAX,
                    limit: max_bytes,
                })
                .at_sequence(sequence)
            })?;
        if captured_bytes > max_bytes {
            return Err(
                CliError::classified(capture::Error::StreamByteLimitExceeded {
                    actual: captured_bytes,
                    limit: max_bytes,
                })
                .at_sequence(sequence),
            );
        }

        let result = match &decoding {
            None => output::capture::Read::try_from_frame(frame)
                .map_err(|source| CliError::classified(source).at_sequence(sequence))?,
            Some((decoder, compiled)) => {
                let decoded = decoder
                    .decode(frame.clone(), decode_options(max_frame_bytes))
                    .map_err(|source| CliError::new(3, source.to_string()).at_sequence(sequence))?;
                if let Some(compiled) = compiled
                    && !compiled.matches(&packet::filter::Context {
                        decoded: &decoded,
                        number: frames,
                        tcp_stream: None,
                        udp_stream: None,
                    })
                {
                    continue;
                }
                if dissect {
                    output::capture::Read::try_from_decoded(frame, &decoded)
                        .map_err(|source| CliError::classified(source).at_sequence(sequence))?
                } else {
                    output::capture::Read::try_from_frame(frame)
                        .map_err(|source| CliError::classified(source).at_sequence(sequence))?
                }
            }
        };

        match output {
            output::contract::Format::Text => match &result.decoded {
                None => write_stdout_line(format_args!(
                    "{sequence}: dlt={} caplen={} wirelen={} {}",
                    result.frame.link_type,
                    result.frame.captured_length,
                    result.frame.original_length,
                    spaced_hex(result.frame.bytes())
                ))?,
                Some(decoded) => write_stdout_line(format_args!(
                    "{sequence}: dlt={} caplen={} wirelen={} layers={} {}",
                    result.frame.link_type,
                    result.frame.captured_length,
                    result.frame.original_length,
                    decoded
                        .packet
                        .layers
                        .iter()
                        .map(|layer| layer.protocol.as_str())
                        .collect::<Vec<_>>()
                        .join("/"),
                    spaced_hex(result.frame.bytes())
                ))?,
            },
            output::contract::Format::Hex => {
                write_plain_line(format_args!("{}", result.frame.bytes_hex))?
            }
            output::contract::Format::Ndjson => {
                emit_json_compact(&output::envelope::Stream::success(
                    output::contract::Command::Read,
                    sequence,
                    result,
                    Vec::new(),
                ))
                .map_err(|error| error.at_sequence(sequence))?
            }
            _ => {
                return Err(CliError::classified(
                    output::contract::Error::UnsupportedFormat {
                        command: output::contract::Command::Read,
                        format: output,
                    },
                ));
            }
        }
        sequence = next_frame_number(sequence, sequence)?;
    }
}

/// Advances a counter, reporting overflow as a sequence-overflow contract error.
fn next_frame_number(value: u64, sequence: u64) -> Result<u64, CliError> {
    value.checked_add(1).ok_or_else(|| {
        CliError::classified(output::contract::Error::SequenceOverflow).at_sequence(sequence)
    })
}

/// Decode bounds derived from the operator's per-frame capture limit.
///
/// The reader already accepted the frame at this size, so the dissector must
/// not then refuse it at its own smaller default.
fn decode_options(max_frame_bytes: usize) -> packet::decode::Options {
    packet::decode::Options {
        max_packet_size: max_frame_bytes,
        ..packet::decode::Options::default()
    }
}

/// Rewrites a capture, keeping only the frames a filter accepts.
///
/// This is a filtering counterpart to `transcode`, which copies every record
/// and so cannot select. Matching frames are written as they are found rather
/// than collected first, so peak memory stays independent of how much of the
/// capture the filter accepts.
///
/// Frame and byte budgets count every frame the input yields, not just the
/// survivors, so filtering can never raise how much input one invocation
/// reads. The writer inherits the same bounds, so an operator who raised a
/// limit to accept an input does not then hit the default on the way out.
fn write_filtered_capture(
    reader: &mut Reader<File>,
    decoder: &packet::decode::Decoder,
    filter: &packet::filter::Filter,
    output: output::contract::Format,
    limits: Limits,
    max_frame_bytes: usize,
    max_interfaces: usize,
) -> Result<(), CliError> {
    let format = capture_file_format(output)?;
    // Classic PCAP declares one link type for the whole file and carries no
    // interface metadata, so `transcode` refuses to write it from a PCAPNG
    // source. Filtering does not change that: deciding the link type from the
    // first surviving frame would commit a header to standard output before a
    // later frame of another link type could be found. Refuse it up front and
    // identically, so a filter never turns a rejected conversion into a
    // half-written file.
    if format == CaptureFormat::Pcap && reader.format() != CaptureFormat::Pcap {
        return Err(CliError::classified(
            capture::Error::MetadataNotRepresentable {
                format: CaptureFormat::Pcap,
                field: "pcapng interface metadata",
            },
        ));
    }
    let stdout = io::stdout().lock();
    let mut writer: Option<Writer<io::StdoutLock<'_>>> = None;
    let mut described = 0_usize;
    let mut frames = 0_u64;
    let mut captured_bytes = 0_u64;

    while let Some(frame) = reader.next_frame().map_err(CliError::classified)? {
        frames = next_frame_number(frames, frames)?;
        if frames > limits.max_frames {
            return Err(CliError::classified(capture::Error::FrameLimitExceeded {
                actual: frames,
                limit: limits.max_frames,
            }));
        }
        captured_bytes = captured_bytes
            .checked_add(u64::from(frame.captured_length()))
            .ok_or_else(|| {
                CliError::classified(capture::Error::StreamByteLimitExceeded {
                    actual: u64::MAX,
                    limit: limits.max_bytes,
                })
            })?;
        if captured_bytes > limits.max_bytes {
            return Err(CliError::classified(
                capture::Error::StreamByteLimitExceeded {
                    actual: captured_bytes,
                    limit: limits.max_bytes,
                },
            ));
        }
        let decoded = decoder
            .decode(frame.clone(), decode_options(max_frame_bytes))
            .map_err(|source| CliError::new(3, source.to_string()))?;
        if !filter.matches(&packet::filter::Context {
            decoded: &decoded,
            number: frames,
            tcp_stream: None,
            udp_stream: None,
        }) {
            continue;
        }

        // The first surviving frame decides the classic-PCAP link type, since
        // a source may declare several interfaces and the filter may keep
        // frames from only one of them.
        let writer = match &mut writer {
            Some(writer) => writer,
            slot => slot.insert(new_capture_writer(
                stdout_handle(&stdout),
                format,
                Some(frame.link_type),
                limits,
                max_frame_bytes,
                max_interfaces,
            )?),
        };
        // PCAPNG interface descriptions are parsed before the frames that
        // reference them, so copying whatever has appeared so far keeps the
        // indices frames carry valid without buffering the capture.
        described = describe_interfaces(writer, reader.interfaces(), described)?;
        writer
            .write_frame(&capture_output_frame(frame, format))
            .map_err(|source| CliError::new(5, format!("write capture output failed: {source}")))?;
    }

    let mut writer = match writer {
        Some(writer) => writer,
        // Accepting nothing is a legitimate result, so an empty subset still
        // writes a readable capture. Every interface is known by now.
        None => {
            let mut writer = new_capture_writer(
                stdout_handle(&stdout),
                format,
                reader
                    .interfaces()
                    .first()
                    .map(|interface| interface.link_type),
                limits,
                max_frame_bytes,
                max_interfaces,
            )?;
            describe_interfaces(&mut writer, reader.interfaces(), 0)?;
            writer
        }
    };
    writer
        .flush()
        .map_err(|source| CliError::new(5, format!("write capture output failed: {source}")))
}

/// Borrows the locked standard output for a capture writer.
///
/// `Writer` owns its sink, and the lock is held for the whole rewrite, so each
/// writer takes a fresh handle onto the same already-locked stream.
fn stdout_handle<'a>(_lock: &'a io::StdoutLock<'a>) -> io::StdoutLock<'a> {
    io::stdout().lock()
}

/// Copies interface descriptions that have appeared since the last call.
///
/// Returns how many are now described, so each is replicated exactly once and
/// the indices frames carry keep pointing at the same interface.
fn describe_interfaces<W: io::Write>(
    writer: &mut Writer<W>,
    interfaces: &[capture::Interface],
    described: usize,
) -> Result<usize, CliError> {
    if writer.format() != CaptureFormat::PcapNg {
        return Ok(described);
    }
    for interface in &interfaces[described..] {
        writer
            .add_interface_description(*interface)
            .map_err(|source| {
                CliError::new(5, format!("initialize capture interface failed: {source}"))
            })?;
    }
    Ok(interfaces.len())
}

/// Builds a capture writer bounded by the same limits the read side was given.
fn new_capture_writer<W: io::Write>(
    sink: W,
    format: CaptureFormat,
    link_type: Option<LinkType>,
    limits: Limits,
    max_frame_bytes: usize,
    max_interfaces: usize,
) -> Result<Writer<W>, CliError> {
    let initialize = |source: capture::Error| {
        CliError::new(5, format!("initialize capture output failed: {source}"))
    };
    let mut writer = if format == CaptureFormat::Pcap {
        // Only classic PCAP declares a link type up front. PCAPNG carries one
        // per interface, so an empty section needs none at all.
        let link_type = link_type.ok_or_else(|| {
            CliError::new(
                2,
                "capture-file output needs a link type, and the input declared none",
            )
        })?;
        Writer::pcap_with_options(
            sink,
            link_type,
            capture::PcapOptions {
                max_size: max_frame_bytes,
                // The snapshot length bounds each record independently of
                // `max_size`, so raising one without the other would still
                // reject the large frame the reader just accepted.
                snap_len: max_frame_bytes,
                ..capture::PcapOptions::default()
            },
        )
        .map_err(initialize)?
    } else {
        Writer::pcapng_with_options(
            sink,
            capture::PcapNgOptions {
                max_size: max_frame_bytes,
                // Every section is normalized into one on the way out, so the
                // output must admit the reader's aggregate allowance rather
                // than one section's worth.
                max_interfaces: max_interfaces.max(capture::DEFAULT_TOTAL_INTERFACE_LIMIT),
                ..capture::PcapNgOptions::default()
            },
        )
        .map_err(initialize)?
    };
    writer
        .set_stream_limits(limits)
        .map_err(|source| CliError::new(2, format!("capture output limits rejected: {source}")))?;
    Ok(writer)
}

/// Strips metadata a classic PCAP record cannot represent.
///
/// Per-frame size is already bounded by the reader, which refuses an oversized
/// record before it is ever allocated, so nothing further is checked here.
fn capture_output_frame(mut frame: Frame, format: CaptureFormat) -> Frame {
    if format == CaptureFormat::Pcap {
        frame.interface = None;
        frame.direction = None;
    }
    frame
}

pub(crate) fn validate_capture_stream_limits(
    max_frames: u64,
    max_bytes: u64,
    max_frame_bytes: usize,
    max_interfaces: usize,
) -> Result<(), CliError> {
    if max_frames == 0 || max_bytes == 0 || max_frame_bytes == 0 || max_interfaces == 0 {
        return Err(CliError::from_classification(
            Classification::new(
                "cli.capture_limit",
                Kind::Cli,
                Some("use finite non-zero capture frame, byte, packet, and interface limits"),
            ),
            "capture stream limits must be non-zero",
            Vec::new(),
        ));
    }
    if u64::try_from(max_frame_bytes).unwrap_or(u64::MAX) > max_bytes {
        return Err(CliError::from_classification(
            Classification::new(
                "cli.capture_limit",
                Kind::Cli,
                Some("set max-frame-bytes no higher than the aggregate max-bytes budget"),
            ),
            format!("max-frame-bytes {max_frame_bytes} exceeds max-bytes {max_bytes}"),
            Vec::new(),
        ));
    }
    Ok(())
}
