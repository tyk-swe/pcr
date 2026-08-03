// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::fs::File;
use std::io;

use packetcraftr::{
    capture::{self, Format as CaptureFormat, Limits, LinkType, Reader, Writer},
    output, packet,
};

use crate::capture_output::CaptureOutput;
use crate::errors::CliError;
use crate::rendering::capture_file_format;

use super::conversion::{decode_options, next_frame_number};

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
pub(super) fn write_filtered_capture(
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
