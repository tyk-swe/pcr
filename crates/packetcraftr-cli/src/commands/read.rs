// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

// Offline capture-read command.

use std::fs::File;
use std::io;

use packetcraftr::{
    capture::{
        self, Format as CaptureFormat, Limits, LinkType, Reader, ReaderOptions, Writer, transcode,
    },
    error::{Classification, Kind},
    output, packet,
};

use super::super::arguments::ReadArgs;
use super::super::capture_output::CaptureOutput;
use super::super::errors::CliError;
use super::super::filtering::{self, Capabilities};
use super::super::input::validate_capture_stream_limits;
use super::super::rendering::{
    capture_file_format, emit_json_compact, spaced_hex, write_plain_line, write_stdout_line,
};
use super::super::runtime::default_registry_arc;

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
    let mut writer: Option<CaptureOutput<io::StdoutLock<'_>>> = None;
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
            slot => slot.insert(new_capture_output(
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
        writer
            .synchronize_source_interfaces(reader.interfaces())
            .map_err(|source| {
                CliError::new(5, format!("initialize capture interface failed: {source}"))
            })?;
        let mut frame = frame;
        if format == CaptureFormat::Pcap {
            frame.direction = None;
        }
        writer
            .write_synchronized_frame(frame)
            .map_err(|source| CliError::new(5, format!("write capture output failed: {source}")))?;
    }

    let mut writer = match writer {
        Some(writer) => writer,
        // Accepting nothing is a legitimate result, so an empty subset still
        // writes a readable capture. Every interface is known by now.
        None => {
            let mut writer = new_capture_output(
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
            writer
                .synchronize_source_interfaces(reader.interfaces())
                .map_err(|source| {
                    CliError::new(5, format!("initialize capture interface failed: {source}"))
                })?;
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

/// Builds a capture writer bounded by the same limits the read side was given.
fn new_capture_output<W: io::Write>(
    sink: W,
    format: CaptureFormat,
    link_type: Option<LinkType>,
    limits: Limits,
    max_frame_bytes: usize,
    max_interfaces: usize,
) -> Result<CaptureOutput<W>, CliError> {
    let initialize = |source: capture::Error| {
        CliError::new(5, format!("initialize capture output failed: {source}"))
    };
    let writer = if format == CaptureFormat::Pcap {
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
    let mut output = CaptureOutput::source_preserving(writer);
    output
        .set_stream_limits(limits)
        .map_err(|source| CliError::new(2, format!("capture output limits rejected: {source}")))?;
    Ok(output)
}
