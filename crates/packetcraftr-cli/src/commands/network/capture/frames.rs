// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Per-frame selection decoding and delivery to every output destination.

use crate::output::envelope::Published;
use std::io;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use packetcraftr::capture::{Control, Source};
use packetcraftr_core::filter::FrameDecoder;
use packetcraftr_core::{
    self as core,
    capture_file::{self, compression},
    decode::DecodedPacket,
    error::BoundaryError,
    frame::Frame,
    registry::Registry,
};

use super::files::Files;
use super::writer;
use crate::command_options::Compression;
use crate::errors::CliError;
use crate::filtering;
use crate::output::{self, contract::Format};
use crate::rendering::{FieldTree, render_frame, write_hex_line};

/// Selection decodes a kept frame once and parks it so emission republishes
/// the same dissection; decoded state never outlives one frame.
pub(super) struct Decoding {
    frames: FrameDecoder,
    parked: Option<(u64, DecodedPacket)>,
    /// Set by `--tree`; text frames then list each layer's fields.
    pub(super) tree: Option<FieldTree>,
}

impl Decoding {
    pub(super) fn prepare(
        dissect: bool,
        projector: bool,
        filter: Option<&str>,
        registry: &Arc<Registry>,
        snap_length: usize,
    ) -> Result<Option<Self>, CliError> {
        if !dissect && !projector {
            return Ok(None);
        }
        Ok(Some(Self {
            frames: filtering::frame_decoder(registry, filter, snap_length)?,
            parked: None,
            tree: None,
        }))
    }

    pub(super) fn select(&mut self, source_frame: u64, frame: &Frame) -> Result<bool, CliError> {
        let Some(decoded) = self
            .frames
            .decode_selected(source_frame, frame)
            .map_err(|error| filtering::frame_error(source_frame, error))?
        else {
            return Ok(false);
        };
        self.parked = Some((source_frame, decoded));
        Ok(true)
    }

    fn take_or_decode(
        &mut self,
        source_frame: u64,
        frame: &Frame,
    ) -> Result<DecodedPacket, CliError> {
        if let Some((number, decoded)) = self.parked.take()
            && number == source_frame
        {
            return Ok(decoded);
        }
        self.frames.decode(frame).map_err(CliError::classified)
    }
}

/// Every place a captured frame goes: files, binary stdout, and projections.
pub(super) struct Destinations {
    pub(super) files: Option<Files>,
    pub(super) writer: Option<capture_file::Writer<compression::Output<io::Stdout>>>,
    pub(super) projector: Option<crate::rendering::Projector>,
    pub(super) format: Format,
    pub(super) compression: Compression,
    pub(super) limits: capture_file::Limits,
}

impl Destinations {
    pub(super) fn start(&mut self, sources: Vec<Source>) -> Result<(), BoundaryError> {
        if let Some(files) = &mut self.files {
            files
                .initialize(sources)
                .map_err(BoundaryError::from_error)?;
        } else if matches!(self.format, Format::Pcap | Format::PcapNg) {
            let destination = compression::Output::new(io::stdout(), self.compression.format())
                .map_err(BoundaryError::from_error)?;
            self.writer = Some(
                writer::initialize(
                    destination,
                    if self.format == Format::Pcap {
                        capture_file::Format::Pcap
                    } else {
                        capture_file::Format::PcapNg
                    },
                    &sources,
                    self.limits,
                )
                .map_err(BoundaryError::from_error)?,
            );
        }
        Ok(())
    }

    pub(super) fn frame(
        &mut self,
        invocation: &crate::invocation::Invocation,
        decoding: Option<&Mutex<Decoding>>,
        source_frame: u64,
        elapsed: Duration,
        frame: Frame,
    ) -> Result<Control, BoundaryError> {
        let control = if let Some(files) = &mut self.files {
            files
                .write(&frame, source_frame, elapsed)
                .map_err(BoundaryError::from_error)?
        } else {
            Control::Continue
        };
        if control == Control::StopBefore {
            return Ok(control);
        }
        let mut decoding = decoding.map(super::lock);
        emit_frame(
            invocation,
            decoding.as_deref_mut(),
            self.projector.as_mut(),
            &mut self.writer,
            source_frame,
            frame,
        )
        .map_err(CliError::into_boundary_error)?;
        Ok(control)
    }

    /// Finalizes every initialized destination even when capture or a consumer
    /// failed; finalization failures chain behind `error`.
    pub(super) fn finish(
        &mut self,
        mut error: Option<CliError>,
    ) -> (Option<CliError>, Option<output::capture::Files>) {
        let file_finish = self
            .files
            .as_mut()
            .map(Files::finish)
            .transpose()
            .map_err(CliError::classified);
        let binary_finish = self
            .writer
            .take()
            .map(|writer| writer.into_inner().finish())
            .transpose()
            .map_err(CliError::classified);
        let files = self.files.as_ref().map(Files::report);
        for failure in [file_finish.err(), binary_finish.err()]
            .into_iter()
            .flatten()
        {
            error = Some(match error.take() {
                Some(primary) => primary.with_secondary("output finalization", failure),
                None => failure,
            });
        }
        (error, files)
    }
}

fn emit_frame(
    invocation: &crate::invocation::Invocation,
    decoding: Option<&mut Decoding>,
    projector: Option<&mut crate::rendering::Projector>,
    writer: &mut Option<capture_file::Writer<compression::Output<io::Stdout>>>,
    source_frame: u64,
    frame: Frame,
) -> Result<(), CliError> {
    let stream = &invocation.output;
    let format = invocation.format;
    if let Some(decoding) = decoding {
        let decoded = decoding.take_or_decode(source_frame, &frame)?;
        let tree = decoding.tree.as_mut();
        if let Some(projector) = projector {
            let values = projector
                .projection
                .values(
                    &core::filter::Context::frame(&decoded, source_frame),
                    projector.remaining(),
                )
                .map_err(CliError::classified)?;
            return projector.emit(source_frame, values, stream);
        }
        return match format {
            Format::Text => {
                let stack = output::frame::Stack::from(&decoded);
                let frame =
                    output::frame::Captured::try_from(frame).map_err(CliError::classified)?;
                let source_frame = source_frame.try_into().map_err(CliError::classified)?;
                match tree {
                    Some(tree) => render_frame(
                        invocation,
                        source_frame,
                        &frame,
                        Some(&stack),
                        Some(tree),
                        crate::invocation::Presentation { verbose: true },
                    ),
                    None => render_frame(
                        invocation,
                        source_frame,
                        &frame,
                        Some(&stack),
                        None,
                        stream.presentation(),
                    ),
                }
            }
            Format::Ndjson => output::read::Frame::try_from((source_frame, frame, &decoded))
                .map_err(CliError::classified)
                .and_then(|record| {
                    stream
                        .emit_published(Published::new(record, Vec::new()))
                        .map_err(Into::into)
                }),
            Format::Json | Format::Hex | Format::Pcap | Format::PcapNg => Err(CliError::new(
                packetcraftr_core::error::Kind::Internal,
                "decoded output requires text or NDJSON",
            )),
            other => other.unreachable(),
        };
    }
    match format {
        Format::Text => output::frame::Captured::try_from(frame)
            .map_err(CliError::classified)
            .and_then(|frame| {
                let source_frame = source_frame.try_into().map_err(CliError::classified)?;
                render_frame(
                    invocation,
                    source_frame,
                    &frame,
                    None,
                    None,
                    stream.presentation(),
                )
            }),
        Format::Hex => output::frame::Captured::try_from(frame)
            .map_err(CliError::classified)
            .and_then(|frame| write_hex_line(frame.bytes())),
        Format::Ndjson => output::read::Frame::try_from((source_frame, frame))
            .map_err(CliError::classified)
            .and_then(|record| {
                stream
                    .emit_published(Published::new(record, Vec::new()))
                    .map_err(Into::into)
            }),
        Format::Json => Ok(()),
        Format::Pcap | Format::PcapNg => writer::write_frame(
            writer.as_mut().expect("writer initialized before frames"),
            frame,
        )
        .map_err(CliError::classified),
        other => other.unreachable(),
    }
}
