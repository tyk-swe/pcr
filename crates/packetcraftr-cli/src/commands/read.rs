// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

pub(super) mod arguments;
mod projection;
mod rendering;
#[cfg(test)]
mod tests;

use crate::output::contract::ReadFormat;

use std::collections::BTreeMap;
use std::io::{self, Read, Write};
use std::sync::Arc;

use packetcraftr_core as core;
use packetcraftr_core::capture_file as capture;
use packetcraftr_core::capture_file::Limits;
use packetcraftr_core::capture_file::Reader;
use packetcraftr_core::capture_file::rewrite;
use packetcraftr_core::error::Classification;
use packetcraftr_core::error::Kind;
use packetcraftr_core::registry::Registry;

use crate::output;

use self::arguments::Args;
use crate::command_options::{FrameSelection, OfflineCaptureLimitsArgs};
use crate::errors::CliError;
use crate::filtering;
use crate::input::open_capture;
use crate::rendering::{FieldTree, StreamEncoder, finish_compressed_output};
use packetcraftr_core::filter::FrameDecoder;

use super::increment_counter;
use rendering::render_record;

struct Decoding {
    frames: FrameDecoder,
    publish_layers: bool,
}

struct StreamState {
    budget: capture::Budget,
    frames_matched: u64,
}

impl StreamState {
    fn new(limits: OfflineCaptureLimitsArgs) -> Result<Self, CliError> {
        let budget = capture::Budget::new(limits.stream_limits()).map_err(CliError::classified)?;
        Ok(Self {
            budget,
            frames_matched: 0,
        })
    }
}

impl super::Spec for Args {
    type Format = crate::output::contract::ReadFormat;
    const CANCELLATION: bool = true;
    const OFFLINE: bool = true;

    fn resources(&self, settings: &mut crate::resources::Settings<'_>) {
        crate::resources::declare!(settings, self, [max_projection_bytes: Bytes @ ResultRetention]);
        self.limits.resources(settings);
        self.tree.resources(settings);
    }

    fn run(
        self,
        format: Self::Format,
        stream: &crate::rendering::StreamEncoder,
    ) -> Result<super::CommandExit, CliError> {
        run(self, format, stream).map(|()| super::CommandExit::SUCCESS)
    }
}

pub(super) fn run(
    arguments: Args,
    format: ReadFormat,
    stream: &StreamEncoder,
) -> Result<(), CliError> {
    let compression = arguments.compression.for_output(format.as_format())?;
    if !arguments.fields.is_empty() {
        return projection::run(arguments, format.as_format(), stream);
    }
    if matches!(format, ReadFormat::Json | ReadFormat::Csv | ReadFormat::Tsv) {
        return Err(crate::rendering::missing_fields_error());
    }
    let Args {
        fields: _,
        max_projection_bytes: _,
        compression: _,
        path,
        limits,
        epoch,
        selection,
        filter,
        normalize,
        dissect,
        tree,
        decode,
    } = arguments;
    limits.validate()?;
    let bounds = epoch.resolve()?;
    let selection = selection.resolve()?;
    validate_dissect_format(dissect, format)?;
    if tree.tree && !dissect {
        return Err(CliError::from_classification(
            Classification::new(
                "cli.tree_requires_dissect",
                Kind::Usage,
                Some("add --dissect to show each frame's layers as a tree"),
            ),
            "--tree requires --dissect",
            Vec::new(),
        ));
    }
    tree.validate_format(format == ReadFormat::Text, format)?;
    let normalize_format = normalize
        .then(|| match format {
            ReadFormat::Pcap => Ok(capture::Format::Pcap),
            ReadFormat::PcapNg => Ok(capture::Format::PcapNg),
            _ => Err(CliError::from_classification(
                Classification::new(
                    "cli.capture_normalize_format",
                    Kind::Usage,
                    Some("use --normalize with --output pcapng or --output pcap"),
                ),
                "--normalize requires PCAP or PCAPNG output",
                Vec::new(),
            )),
        })
        .transpose()?;
    let rewrite_format = match format {
        ReadFormat::Pcap => Some(capture::Format::Pcap),
        ReadFormat::PcapNg => Some(capture::Format::PcapNg),
        _ => None,
    };
    let registry = decode.registry()?;
    let decoding = prepare_decoding(
        filter.as_deref(),
        dissect,
        &registry,
        limits.reader.max_frame_bytes,
    )?;
    let mut tree = tree
        .tree
        .then(|| FieldTree::new(Arc::clone(&registry), tree.max_tree_bytes));
    let mut reader = open_capture(&path, limits.reader)?;
    if let Some(normalize_format) = normalize_format {
        let stdout = io::stdout();
        let mut destination = compression.writer(stdout.lock())?;
        let result = normalize_capture(
            &mut reader,
            limits,
            Selection {
                bounds,
                frames: &selection,
                decoding: decoding.as_ref(),
            },
            normalize_format,
            &mut destination,
        );
        return finish_compressed_output(result, destination);
    }
    if let Some(rewrite_format) = rewrite_format {
        validate_rewrite_format(reader.format(), rewrite_format)?;
        let stdout = io::stdout();
        let mut destination = compression.writer(stdout.lock())?;
        let result = rewrite_capture(
            &mut reader,
            limits.stream_limits(),
            Selection {
                bounds,
                frames: &selection,
                decoding: decoding.as_ref(),
            },
            &mut destination,
        );
        return finish_compressed_output(result, destination);
    }
    read_records(
        &mut reader,
        limits,
        Selection {
            bounds,
            frames: &selection,
            decoding: decoding.as_ref(),
        },
        format,
        stream,
        tree.as_mut(),
    )
}

fn validate_dissect_format(dissect: bool, format: ReadFormat) -> Result<(), CliError> {
    if dissect && !matches!(format, ReadFormat::Text | ReadFormat::Ndjson) {
        return Err(CliError::from_classification(
            Classification::new(
                "cli.dissect_unsupported_format",
                Kind::Usage,
                Some("use --output text or --output ndjson to show the layer stack"),
            ),
            format!("--dissect has no effect on {format} output"),
            Vec::new(),
        ));
    }
    Ok(())
}

fn prepare_decoding(
    filter: Option<&str>,
    dissect: bool,
    registry: &Arc<Registry>,
    max_frame_bytes: usize,
) -> Result<Option<Decoding>, CliError> {
    if filter.is_none() && !dissect {
        return Ok(None);
    }
    Ok(Some(Decoding {
        frames: filtering::frame_decoder(registry, filter, max_frame_bytes)?,
        publish_layers: dissect,
    }))
}

/// Which source frames a run keeps, before any frame is decoded for display.
#[derive(Clone, Copy)]
struct Selection<'a> {
    bounds: Option<core::frame::TimeBounds>,
    frames: &'a FrameSelection,
    decoding: Option<&'a Decoding>,
}

impl Selection<'_> {
    /// Position and time selectors only; decoding for `--filter` is separate.
    fn keeps(&self, number: u64, frame: &core::frame::Frame) -> bool {
        self.frames.keeps(number)
            && self
                .bounds
                .is_none_or(|bounds| bounds.contains(frame.timestamp))
    }
}

/// Checked before stdout is wrapped, so a rejected conversion writes no compressed container.
fn validate_rewrite_format(
    input: capture::Format,
    output: capture::Format,
) -> Result<(), CliError> {
    if output != input {
        return Err(CliError::from_classification(
            Classification::new(
                "cli.capture_rewrite_format",
                Kind::Usage,
                Some("select the capture output format matching the input capture"),
            ),
            format!(
                "capture rewriting cannot convert {input} input to {output} without normalization"
            ),
            Vec::new(),
        ));
    }
    Ok(())
}

fn rewrite_capture(
    reader: &mut Reader<impl Read>,
    limits: Limits,
    selection: Selection<'_>,
    destination: &mut impl Write,
) -> Result<(), CliError> {
    if selection.decoding.is_none()
        && selection.bounds.is_none()
        && selection.frames.is_unrestricted()
    {
        return rewrite(reader, destination, limits)
            .map(|_| ())
            .map_err(CliError::classified);
    }
    capture::select(reader, destination, limits, |number, frame| {
        if !selection.keeps(number, frame) {
            return Ok(false);
        }
        let Some(decoding) = selection.decoding else {
            return Ok(true);
        };
        decoding
            .frames
            .decode_selected(number, frame)
            .map(|decoded| decoded.is_some())
            .map_err(|error| filtering::frame_error(number, error).into_boundary_error())
    })
    .map(|_| ())
    .map_err(CliError::classified)
}

fn read_records(
    reader: &mut Reader<impl Read>,
    limits: OfflineCaptureLimitsArgs,
    selection: Selection<'_>,
    format: ReadFormat,
    stream: &StreamEncoder,
    mut tree: Option<&mut FieldTree>,
) -> Result<(), CliError> {
    let mut state = StreamState::new(limits)?;
    while let Some(frame) = reader.next_frame().map_err(CliError::classified)? {
        let source_frame = account_frame(&mut state, &frame)?;
        if !selection.keeps(source_frame, &frame) {
            continue;
        }
        let Some(record) = convert_frame(frame, source_frame, selection.decoding)? else {
            continue;
        };
        render_record(record, format, stream, tree.as_deref_mut())?;
        state.frames_matched = increment_counter(state.frames_matched, "read matched-frame count")?;
    }
    if format == ReadFormat::Ndjson {
        stream.complete(
            output::read::Event::from(output::read::Totals::from((
                &state.budget,
                state.frames_matched,
            ))),
            Vec::new(),
        )?;
    }
    Ok(())
}

/// The next frame that passes every selector, with its source position.
///
/// Every frame read is charged to the input budget, selected or not, and the reader is
/// checked for a declared frame check sequence after each read.
fn next_selected(
    reader: &mut Reader<impl Read>,
    state: &mut StreamState,
    selection: Selection<'_>,
) -> Result<Option<(u64, core::frame::Frame)>, CliError> {
    loop {
        let next = reader.next_frame().map_err(CliError::classified)?;
        reader.refuse_declared_fcs().map_err(CliError::classified)?;
        let Some(frame) = next else { return Ok(None) };
        let source_frame = account_frame(state, &frame)?;
        if !selection.keeps(source_frame, &frame) {
            continue;
        }
        if let Some(decoding) = selection.decoding
            && decoding
                .frames
                .decode_selected(source_frame, &frame)
                .map_err(|error| filtering::frame_error(source_frame, error))?
                .is_none()
        {
            continue;
        }
        return Ok(Some((source_frame, frame)));
    }
}

fn normalize_capture(
    reader: &mut Reader<impl Read>,
    limits: OfflineCaptureLimitsArgs,
    selection: Selection<'_>,
    format: capture::Format,
    destination: impl Write,
) -> Result<(), CliError> {
    reader.refuse_declared_fcs().map_err(CliError::classified)?;
    match format {
        capture::Format::PcapNg => normalize_to_pcapng(reader, limits, selection, destination),
        capture::Format::Pcap => normalize_to_pcap(reader, limits, selection, destination),
    }
}

fn normalize_to_pcapng(
    reader: &mut Reader<impl Read>,
    limits: OfflineCaptureLimitsArgs,
    selection: Selection<'_>,
    destination: impl Write,
) -> Result<(), CliError> {
    let mut writer = capture::Writer::pcapng_with_options(
        destination,
        capture::PcapNgOptions {
            max_size: limits.reader.max_frame_bytes,
            max_interfaces: limits.reader.max_interfaces,
            stream_limits: limits.stream_limits(),
            ..capture::PcapNgOptions::default()
        },
    )
    .map_err(CliError::classified)?;
    let mut interfaces = BTreeMap::new();
    let mut state = StreamState::new(limits)?;
    while let Some((_, mut frame)) = next_selected(reader, &mut state, selection)? {
        // Classic PCAP exposes its single interface at zero; PCAPNG frame IDs are global.
        let source_interface = frame.interface.unwrap_or(0);
        let output_interface = match interfaces.get(&source_interface) {
            Some(interface) => *interface,
            None => {
                let description = source_description(reader, source_interface).clone();
                let output_interface = writer
                    .add_interface_description(description)
                    .map_err(CliError::classified)?;
                interfaces.insert(source_interface, output_interface);
                output_interface
            }
        };
        frame.interface = Some(output_interface);
        writer.write_frame(&frame).map_err(CliError::classified)?;
    }
    writer.flush().map_err(CliError::classified)
}

fn source_description<R: Read>(reader: &Reader<R>, source_interface: u32) -> &capture::Interface {
    let source_index = usize::try_from(source_interface)
        .expect("reader interface IDs fit the in-memory interface table");
    reader
        .interfaces()
        .get(source_index)
        .expect("reader registers each frame interface before returning the frame")
}

/// Classic PCAP fixes its header before the first record, so the writer opens at the first
/// selected frame, and a later conflict can leave the earlier records already written.
fn normalize_to_pcap<W: Write>(
    reader: &mut Reader<impl Read>,
    limits: OfflineCaptureLimitsArgs,
    selection: Selection<'_>,
    destination: W,
) -> Result<(), CliError> {
    let mut state = StreamState::new(limits)?;
    let mut destination = Some(destination);
    let mut open: Option<(u32, capture::Writer<W>)> = None;
    while let Some((source_frame, mut frame)) = next_selected(reader, &mut state, selection)? {
        let source_interface = frame.interface.unwrap_or(0);
        if open.is_none() {
            let opened = open_classic_writer(
                destination.take().expect("the writer opens once"),
                source_description(reader, source_interface),
                limits,
            )?;
            open = Some((source_interface, opened));
        }
        let Some((first_interface, writer)) = open.as_mut() else {
            unreachable!("the writer opened above");
        };
        if source_interface != *first_interface {
            return Err(pcap_conflict(
                source_frame,
                (
                    *first_interface,
                    source_description(reader, *first_interface),
                ),
                (
                    source_interface,
                    source_description(reader, source_interface),
                ),
            ));
        }
        match frame.direction {
            None | Some(core::frame::Direction::Unknown) => frame.direction = None,
            Some(_) => return Err(pcap_direction_error(source_frame)),
        }
        frame.interface = None;
        writer.write_frame(&frame).map_err(CliError::classified)?;
    }
    match open {
        Some((_, mut writer)) => writer.flush().map_err(CliError::classified),
        None => Err(CliError::from_classification(
            Classification::new(
                "cli.capture_normalize_pcap",
                Kind::Usage,
                Some("select at least one frame, or use --output pcapng for an empty capture"),
            ),
            "classic PCAP output needs one selected frame to choose its link type",
            Vec::new(),
        )),
    }
}

fn open_classic_writer<W: Write>(
    destination: W,
    description: &capture::Interface,
    limits: OfflineCaptureLimitsArgs,
) -> Result<capture::Writer<W>, CliError> {
    let timestamp_resolution = match description.timestamp_resolution {
        resolution @ (capture::TimestampResolution::Decimal(6)
        | capture::TimestampResolution::Decimal(9)) => resolution,
        capture::TimestampResolution::Decimal(exponent) => {
            return Err(pcap_resolution_error(format!("10^-{exponent} s")));
        }
        capture::TimestampResolution::Binary(exponent) => {
            return Err(pcap_resolution_error(format!("2^-{exponent} s")));
        }
    };
    // PCAPNG marks an unlimited snapshot with zero; classic PCAP needs a finite header value.
    let snap_len = match description.snap_len {
        0 => limits.reader.max_frame_bytes,
        snap_len => usize::try_from(snap_len).unwrap_or(usize::MAX),
    };
    capture::Writer::pcap_with_options(
        destination,
        description.link_type,
        capture::PcapOptions {
            timestamp_resolution,
            snap_len,
            max_size: limits.reader.max_frame_bytes,
            stream_limits: limits.stream_limits(),
            ..capture::PcapOptions::default()
        },
    )
    .map_err(CliError::classified)
}

fn pcap_metadata_error(message: String) -> CliError {
    CliError::from_classification(
        Classification::new(
            "packet.capture_transform_metadata",
            Kind::Packet,
            Some("use --output pcapng to keep capture metadata classic PCAP cannot carry"),
        ),
        message,
        Vec::new(),
    )
}

fn pcap_direction_error(source_frame: u64) -> CliError {
    pcap_metadata_error(format!(
        "pcap cannot represent direction (frame {source_frame} is marked inbound or outbound)"
    ))
}

fn pcap_resolution_error(resolution: String) -> CliError {
    pcap_metadata_error(format!(
        "pcap cannot represent the source timestamp resolution {resolution}; \
         classic PCAP holds microseconds or nanoseconds"
    ))
}

fn pcap_conflict(
    source_frame: u64,
    first: (u32, &capture::Interface),
    other: (u32, &capture::Interface),
) -> CliError {
    pcap_metadata_error(format!(
        "pcap holds one interface, but selected frames use interface {} (link type {}) and \
         interface {} (link type {}) at frame {source_frame}",
        first.0, first.1.link_type.0, other.0, other.1.link_type.0,
    ))
}

fn account_frame(state: &mut StreamState, frame: &core::frame::Frame) -> Result<u64, CliError> {
    crate::cancellation::check()?;
    state
        .budget
        .charge(frame.captured_length())
        .map_err(CliError::classified)?;
    Ok(state.budget.frames())
}

fn convert_frame(
    frame: core::frame::Frame,
    source_frame: u64,
    decoding: Option<&Decoding>,
) -> Result<Option<output::read::Frame>, CliError> {
    let Some(decoding) = decoding else {
        return output::read::Frame::try_from((source_frame, frame))
            .map(Some)
            .map_err(CliError::classified);
    };
    let Some(decoded) = decoding
        .frames
        .decode_selected(source_frame, &frame)
        .map_err(|error| filtering::frame_error(source_frame, error))?
    else {
        return Ok(None);
    };
    if decoding.publish_layers {
        output::read::Frame::try_from((source_frame, frame, &decoded))
    } else {
        output::read::Frame::try_from((source_frame, frame))
    }
    .map(Some)
    .map_err(CliError::classified)
}
