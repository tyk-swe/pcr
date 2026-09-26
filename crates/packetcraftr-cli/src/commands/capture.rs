// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! `capture`: streams live frames from one or more interfaces to text,
//! NDJSON, a capture stream, or rotating capture files.

pub(super) mod arguments;
mod files;
mod rendering;
#[cfg(test)]
mod tests;
mod writer;

use self::arguments::Args;
use crate::output::{
    capture::Retention,
    contract::{CaptureFormat, Command},
};
use crate::{
    errors::CliError, filtering::FrameSelector, rendering::StreamEncoder, system::resolve,
};
use packetcraftr_core::{capture_file, error::Kind};
use packetcraftr_netio as net;
use std::{collections::HashSet, time::Duration};

use self::files::Files;
use crate::command_options::Compression;
use crate::filtering::FrameDecoder;
use crate::output;
use crate::rendering::{render_frame_text, write_plain_line};
use packetcraftr::capture::{self as workflow, Control, Event};
use packetcraftr_core::{
    self as core,
    capture_file::compression,
    decode::DecodedPacket,
    error::{BoundaryError, Classified},
    frame::Frame,
    registry::Registry,
};
use packetcraftr_netio::capture::{Provider, group};
use std::cell::RefCell;
use std::io;
use std::sync::Arc;

impl super::Spec for Args {
    type Format = crate::output::contract::CaptureFormat;
    const CANCELLATION: bool = true;

    fn resources(&self, settings: &mut crate::resources::Settings<'_>) {
        crate::resources::declare!(settings, self, [
            rotate_bytes: Bytes @ CaptureStorage,
            rotate_interval_ms: Milliseconds @ CaptureStorage,
            rotate_files: Count @ CaptureStorage,
            retention: Policy @ CaptureStorage,
            max_projection_bytes: Bytes @ ResultRetention,
        ]);
        self.timeout.resources(settings);
        self.limits.resources(settings);
        self.budgets.resources(settings);
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
    args: Args,
    format: CaptureFormat,
    stream: &StreamEncoder,
) -> Result<(), CliError> {
    // Parsing bounded the window to the capture ceiling.
    let timeout = args.timeout.timeout();
    if args.interface.len() > 256 {
        return Err(CliError::new(
            Kind::Usage,
            "capture accepts at most 256 interface selectors before deduplication",
        ));
    }
    let compression = if args.write.is_some() {
        if !matches!(
            format,
            CaptureFormat::Text | CaptureFormat::Json | CaptureFormat::Ndjson
        ) {
            return Err(CliError::new(
                Kind::Usage,
                "--write requires text, JSON, or NDJSON reporting",
            ));
        }
        args.compression.for_file()
    } else {
        let compression = args.compression.for_output(format.as_format())?;
        if args.rotate_bytes.is_some()
            || args.rotate_interval_ms.is_some()
            || args.rotate_files != 1
            || Retention::from(args.retention) != Retention::Stop
        {
            return Err(CliError::new(
                Kind::Usage,
                "capture rotation requires --write",
            ));
        }
        if format == CaptureFormat::Json {
            return Err(CliError::new(
                Kind::Usage,
                "JSON capture summaries require --write to retain packet data",
            ));
        }
        compression
    };
    if (args.dissect || !args.fields.is_empty())
        && !matches!(format, CaptureFormat::Text | CaptureFormat::Ndjson)
    {
        return Err(CliError::from_classification(
            packetcraftr_core::error::Classification::new(
                "cli.capture_decode_format",
                Kind::Usage,
                Some("use --output text or --output ndjson for decoded frame output"),
            ),
            "--dissect and --field require text or NDJSON output",
            Vec::new(),
        ));
    }
    let limits = args.limits.into_limits();
    limits.validate().map_err(CliError::classified)?;
    let native = net::capture::NativeSettings {
        buffer_size: args.capture_buffer_bytes,
        timestamp_source: args.timestamp_source.map(Into::into),
        timestamp_precision: args.timestamp_precision.map(Into::into),
    };
    native.validate(&limits).map_err(CliError::classified)?;
    let registry = args.decode.registry()?;
    let projector = if args.fields.is_empty() {
        None
    } else {
        super::projection::Projector::prepare(
            &args.fields,
            args.max_projection_bytes,
            &registry,
            Command::Capture,
            format.as_format(),
        )?
    };
    let decoding = Decoding::prepare(
        args.dissect,
        projector.is_some(),
        args.filter.as_deref(),
        &registry,
        limits.snap_length,
    )?;
    // The raw selector remains the filter's owner when no output decoding was
    // requested; `Decoding` otherwise evaluates the same filter itself so a
    // frame is decoded at most once.
    let selector = if decoding.is_none() {
        FrameSelector::compile_optional(args.filter.as_deref(), &registry, limits.snap_length)?
    } else {
        None
    };
    let policy = args.budgets.into_policy();
    let budget = packetcraftr::policy::CaptureBudget::new(&policy);
    let files = args
        .write
        .map(|path| {
            files::Files::new(
                files::Options {
                    path,
                    compression,
                    rotate_bytes: args.rotate_bytes,
                    rotate_after: args.rotate_interval_ms.map(Duration::from_millis),
                    max_files: args.rotate_files,
                    retention: args.retention.into(),
                },
                capture_file::Limits {
                    max_frames: budget.max_frames(),
                    max_bytes: budget.max_bytes(),
                },
            )
        })
        .transpose()
        .map_err(CliError::classified)?;
    let mut seen = HashSet::new();
    let mut interfaces = Vec::new();
    for source in args.interface {
        let interface = resolve(source, &net::interface::SystemProvider)?;
        if seen.insert(interface.index) {
            interfaces.push(interface);
        }
    }
    if format == CaptureFormat::Pcap && interfaces.len() != 1 {
        return Err(CliError::new(
            Kind::Usage,
            "multiple interfaces require PCAPNG capture output",
        ));
    }
    let request = net::capture::group::Request {
        interfaces,
        limits,
        filter: args.capture_filter,
        promiscuous: args.promiscuous,
        native,
    };
    drive(
        &net::capture::SystemProvider,
        &request,
        packetcraftr::capture::Options {
            window: timeout,
            budget,
            cancellation: Some(crate::cancellation::signal().clone()),
        },
        Output {
            format,
            compression,
            selector,
            decoding,
            projector,
            files,
            stream,
        },
    )
}

/// Shared per-frame decoding for `--filter`, `--dissect`, and `--field`.
/// Selection decodes a kept frame once and parks it so emission republishes
/// the same dissection; decoded state never outlives one frame.
struct Decoding {
    frames: FrameDecoder,
    parked: RefCell<Option<(u64, DecodedPacket)>>,
}

impl Decoding {
    /// Builds the shared decoding state, or `None` when neither `--dissect`
    /// nor `--field` asked for decoded output. `parked` starts empty.
    fn prepare(
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
            frames: FrameDecoder::compile(registry, filter, snap_length)?,
            parked: RefCell::new(None),
        }))
    }

    /// The filter half of frame selection, run by the capture admission
    /// callback; a kept frame's dissection is parked for the emit callback.
    fn select(&self, source_frame: u64, frame: &Frame) -> Result<bool, CliError> {
        let Some(decoded) = self.frames.decode_selected(source_frame, frame)? else {
            return Ok(false);
        };
        self.parked.replace(Some((source_frame, decoded)));
        Ok(true)
    }

    /// Reuses the dissection `select` parked for this frame, decoding only
    /// when no selection ran for it (the no-filter case).
    fn take_or_decode(&self, source_frame: u64, frame: &Frame) -> Result<DecodedPacket, CliError> {
        if let Some((number, decoded)) = self.parked.take()
            && number == source_frame
        {
            return Ok(decoded);
        }
        self.frames.decode(frame)
    }
}

/// Where a capture's frames and summary go.
struct Output<'a> {
    format: CaptureFormat,
    compression: Compression,
    selector: Option<FrameSelector>,
    decoding: Option<Decoding>,
    projector: Option<super::projection::Projector>,
    files: Option<Files>,
    stream: &'a StreamEncoder,
}
/// Provider composition is injected so normal capture, rotation, and mixed
/// interfaces all exercise the same workflow and finalization path.
fn drive<P: Provider>(
    provider: &P,
    request: &group::Request,
    options: workflow::Options,
    mut rendering: Output<'_>,
) -> Result<(), CliError> {
    let limits = capture_file::Limits {
        max_frames: options.budget.max_frames(),
        max_bytes: options.budget.max_bytes(),
    };
    let mut writer: Option<capture_file::Writer<compression::Output<io::Stdout>>> = None;
    let format = rendering.format;
    let result = workflow::run(
        provider,
        request,
        options,
        |number, frame| {
            if let Some(decoding) = &rendering.decoding {
                return decoding
                    .select(number, frame)
                    .map_err(CliError::into_boundary_error);
            }
            rendering
                .selector
                .as_ref()
                .map(|selector| selector.keep(number, frame))
                .transpose()
                .map_err(CliError::into_boundary_error)
                .map(|keep| keep.unwrap_or(true))
        },
        |event| match event {
            Event::Started { sources } => {
                if let Some(files) = &mut rendering.files {
                    files
                        .initialize(sources)
                        .map_err(BoundaryError::from_error)?;
                } else if matches!(format, CaptureFormat::Pcap | CaptureFormat::PcapNg) {
                    let destination =
                        compression::Output::new(io::stdout(), rendering.compression.format())
                            .map_err(BoundaryError::from_error)?;
                    writer = Some(
                        writer::initialize(
                            destination,
                            if format == CaptureFormat::Pcap {
                                capture_file::Format::Pcap
                            } else {
                                capture_file::Format::PcapNg
                            },
                            &sources,
                            limits,
                        )
                        .map_err(BoundaryError::from_error)?,
                    );
                }
                Ok(Control::Continue)
            }
            Event::Frame {
                source_frame,
                elapsed,
                frame,
                ..
            } => {
                let control = if let Some(files) = &mut rendering.files {
                    files
                        .write(&frame, source_frame, elapsed)
                        .map_err(BoundaryError::from_error)?
                } else {
                    Control::Continue
                };
                if control == Control::StopBefore {
                    return Ok(control);
                }
                let emitted = emit_frame(
                    rendering.decoding.as_ref(),
                    rendering.projector.as_mut(),
                    rendering.stream,
                    format,
                    &mut writer,
                    source_frame,
                    frame,
                );
                emitted.map_err(CliError::into_boundary_error)?;
                Ok(control)
            }
        },
    );
    // Finalize every initialized destination even when capture or a consumer
    // failed, retaining whatever complete records reached the writer.
    let file_finish = rendering
        .files
        .as_mut()
        .map(Files::finish)
        .transpose()
        .map_err(CliError::classified);
    let binary_finish = writer
        .map(|writer| writer.into_inner().finish())
        .transpose()
        .map_err(CliError::classified);
    let files = rendering.files.as_ref().map(Files::report);
    let (report, mut error) = match result {
        Ok(report) => (report, None),
        Err(error) => {
            let cli = CliError::from_classification(
                error.classification(),
                error.to_string(),
                error.causes(),
            )
            .with_context(error.context());
            (*error.report, Some(cli))
        }
    };
    for failure in [file_finish.err(), binary_finish.err()]
        .into_iter()
        .flatten()
    {
        error = Some(match error.take() {
            Some(primary) => primary.with_secondary("output finalization", failure),
            None => failure,
        });
    }

    let summary = output::capture::Summary::from_capture(&report, files);
    if let Some(error) = error {
        return Err(error.with_capture(output::capture::Snapshot {
            summary,
            stats: report.stats,
        }));
    }
    // A projection that never matched a frame still owes its text header; the
    // NDJSON terminal is the capture summary, never a second complete record.
    if format == CaptureFormat::Text
        && let Some(projector) = rendering.projector.take()
    {
        projector
            .finish(
                report.frames_delivered,
                report.stats.bytes,
                rendering.stream,
            )
            .map_err(|error| {
                error.with_capture(output::capture::Snapshot {
                    summary: summary.clone(),
                    stats: report.stats.clone(),
                })
            })?;
    }
    rendering::render_complete(
        format,
        &summary,
        &report.stats,
        report.diagnostics,
        rendering.stream,
    )
    .map_err(|error| {
        error.with_capture(output::capture::Snapshot {
            summary,
            stats: report.stats,
        })
    })
}

/// Publishes one matched frame. Decoded output reuses the dissection the
/// admission callback parked, projections stream as bounded `fields` records,
/// and every sink error propagates so capture cleanup still runs.
fn emit_frame(
    decoding: Option<&Decoding>,
    projector: Option<&mut super::projection::Projector>,
    stream: &StreamEncoder,
    format: CaptureFormat,
    writer: &mut Option<capture_file::Writer<compression::Output<io::Stdout>>>,
    source_frame: u64,
    frame: Frame,
) -> Result<(), CliError> {
    if let Some(decoding) = decoding {
        let decoded = decoding.take_or_decode(source_frame, &frame)?;
        if let Some(projector) = projector {
            let values = projector
                .projection
                .values(
                    &core::filter::Context {
                        decoded: &decoded,
                        derived: &[],
                        number: source_frame,
                        tcp_stream: None,
                        udp_stream: None,
                    },
                    projector.remaining(),
                )
                .map_err(CliError::classified)?;
            return projector.emit(source_frame, values, stream);
        }
        return match format {
            CaptureFormat::Text => {
                // Only the text rendering needs a stack here; the NDJSON event
                // builds its own inside `try_from_decoded`.
                let stack = output::frame::Stack::from_decoded(&decoded);
                let frame =
                    output::frame::Captured::try_from_frame(frame).map_err(CliError::classified)?;
                let source_frame = source_frame.try_into().map_err(CliError::classified)?;
                render_frame_text(source_frame, &frame, Some(&stack))
            }
            CaptureFormat::Ndjson => {
                output::capture::Event::try_from_decoded(source_frame, frame, &decoded)
                    .map_err(CliError::classified)
                    .and_then(|event| stream.emit_data(event, Vec::new()).map_err(Into::into))
            }
            CaptureFormat::Json
            | CaptureFormat::Hex
            | CaptureFormat::Pcap
            | CaptureFormat::PcapNg => Err(CliError::new(
                packetcraftr_core::error::Kind::Internal,
                "decoded output requires text or NDJSON",
            )),
        };
    }
    match format {
        CaptureFormat::Text => output::frame::Captured::try_from_frame(frame)
            .map_err(CliError::classified)
            .and_then(|frame| {
                let source_frame = source_frame.try_into().map_err(CliError::classified)?;
                render_frame_text(source_frame, &frame, None)
            }),
        CaptureFormat::Hex => output::frame::Captured::try_from_frame(frame)
            .map_err(CliError::classified)
            .and_then(|frame| write_plain_line(format_args!("{}", frame.bytes_hex()))),
        CaptureFormat::Ndjson => output::capture::Event::try_from_frame(source_frame, frame)
            .map_err(CliError::classified)
            .and_then(|event| stream.emit_data(event, Vec::new()).map_err(Into::into)),
        CaptureFormat::Json => Ok(()),
        CaptureFormat::Pcap | CaptureFormat::PcapNg => writer
            .as_mut()
            .expect("writer initialized before frames")
            .write_frame(&frame)
            .map_err(CliError::classified),
    }
}
