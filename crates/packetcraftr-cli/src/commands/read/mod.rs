// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Read CLI command logic.

pub(super) mod arguments;
mod conversion;
mod rendering;

use std::fs::File;
use std::io;

use packetcraftr::{
    analysis::pcap::{Limits, Reader, ReaderOptions, rewrite},
    output, packet,
    packet::error::{Classification, Kind},
};

use self::arguments::ReadArgs;
use crate::errors::CliError;
use crate::filtering::{self, Capabilities};
use crate::input::validate_capture_stream_limits;
use crate::rendering::capture_file_format;
use crate::system::default_registry_arc;

use conversion::{decode_options, next_frame_number};
use rendering::render_read_record;

pub(super) fn run(arguments: ReadArgs, output: output::contract::Format) -> Result<(), CliError> {
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

    // Dissection is the price of filtering and of showing the layer stack.
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
        if filter.is_some() {
            return Err(CliError::from_classification(
                Classification::new(
                    "cli.capture_rewrite_filter",
                    Kind::Cli,
                    Some("use text, hex, or ndjson output to filter frames"),
                ),
                "capture rewriting cannot filter records without discarding source structure",
                Vec::new(),
            ));
        }
        let format = capture_file_format(output)?;
        if format != reader.format() {
            return Err(CliError::from_classification(
                Classification::new(
                    "cli.capture_rewrite_format",
                    Kind::Cli,
                    Some("select the capture output format matching the input capture"),
                ),
                format!(
                    "capture rewriting cannot convert {:?} input to {format:?} without normalization",
                    reader.format()
                ),
                Vec::new(),
            ));
        }
        let stdout = io::stdout();
        let (_output, _report) =
            rewrite(&mut reader, stdout.lock(), stream_limits).map_err(CliError::classified)?;
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
            return Err(CliError::classified(
                packetcraftr::analysis::pcap::Error::FrameLimitExceeded {
                    actual: frames,
                    limit: max_frames,
                },
            )
            .at_sequence(sequence));
        }
        captured_bytes = captured_bytes
            .checked_add(u64::from(frame.captured_length()))
            .ok_or_else(|| {
                CliError::classified(
                    packetcraftr::analysis::pcap::Error::StreamByteLimitExceeded {
                        actual: u64::MAX,
                        limit: max_bytes,
                    },
                )
                .at_sequence(sequence)
            })?;
        if captured_bytes > max_bytes {
            return Err(CliError::classified(
                packetcraftr::analysis::pcap::Error::StreamByteLimitExceeded {
                    actual: captured_bytes,
                    limit: max_bytes,
                },
            )
            .at_sequence(sequence));
        }

        let result = match &decoding {
            None => output::read::Result::try_from_frame(frame)
                .map_err(|source| CliError::classified(source).at_sequence(sequence))?,
            Some((decoder, compiled)) => {
                let decoded = decoder
                    .decode(frame.clone(), decode_options(max_frame_bytes))
                    .map_err(|source| CliError::new(3, source.to_string()).at_sequence(sequence))?;
                if let Some(compiled) = compiled
                    && compiled.requirements().timestamp
                    && frame.timestamp.is_none()
                {
                    return Err(CliError::from_classification(
                        Classification::new(
                            "packet.timestamp_unavailable",
                            Kind::Packet,
                            Some("remove frame.time_epoch from the filter or use timestamped packet blocks"),
                        ),
                        format!("frame {frames} has no timestamp required by frame.time_epoch"),
                        Vec::new(),
                    )
                    .at_sequence(sequence));
                }
                if let Some(compiled) = compiled
                    && !compiled
                        .matches(&packet::filter::Context {
                            decoded: &decoded,
                            number: frames,
                            tcp_stream: None,
                            udp_stream: None,
                        })
                        .map_err(|source| {
                            CliError::new(3, source.to_string()).at_sequence(sequence)
                        })?
                {
                    continue;
                }
                if dissect {
                    output::read::Result::try_from_decoded(frame, &decoded)
                        .map_err(|source| CliError::classified(source).at_sequence(sequence))?
                } else {
                    output::read::Result::try_from_frame(frame)
                        .map_err(|source| CliError::classified(source).at_sequence(sequence))?
                }
            }
        };

        render_read_record(&result, output, sequence)?;
        sequence = next_frame_number(sequence, sequence)?;
    }
}
