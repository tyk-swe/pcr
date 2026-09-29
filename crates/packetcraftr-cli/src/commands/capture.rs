// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

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
    errors::CliError,
    filtering,
    rendering::StreamEncoder,
    system::{Runtime, client, resolve},
};
use packetcraftr_core::{capture_file, error::Kind};
use packetcraftr_netio as net;
use std::{
    collections::HashSet,
    time::{Duration, Instant},
};

use self::files::Files;
use crate::command_options::Compression;
use crate::output;
use crate::rendering::{render_frame_text, write_hex_line};
use packetcraftr::capture::{self as workflow, Control, Event, Source};
use packetcraftr::policy::{CaptureBudget, Policy};
use packetcraftr_core::filter::{FrameDecoder, FrameSelector};
use packetcraftr_core::{
    self as core,
    capture_file::compression,
    decode::DecodedPacket,
    error::{BoundaryError, Classified},
    frame::Frame,
    registry::Registry,
};
use std::io;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

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
    let timeout = args.timeout.timeout();
    if timeout > net::deadline::MAX_WAIT || Instant::now().checked_add(timeout).is_none() {
        return Err(CliError::classified(net::Error::InvalidCaptureTimeout {
            timeout,
            maximum: net::deadline::MAX_WAIT,
        }));
    }
    if args.interface.len() > 256 {
        return Err(CliError::new(
            Kind::Usage,
            "capture accepts at most 256 interface selectors before deduplication",
        ));
    }
    let compression = validate_output(&args, format)?;
    let limits = args.limits.into_limits();
    limits.validate().map_err(CliError::classified)?;
    let native = net::capture::NativeSettings {
        buffer_size: args.capture_buffer_bytes,
        timestamp_source: args.timestamp_source.map(Into::into),
        timestamp_precision: args.timestamp_precision.map(Into::into),
    };
    native.validate(&limits).map_err(CliError::classified)?;
    let registry = args.decode.registry()?;
    let projector = crate::rendering::Projector::prepare(
        &args.fields,
        args.max_projection_bytes,
        &registry,
        Command::Capture,
        format.as_format(),
    )?;
    if projector
        .as_ref()
        .is_some_and(|projector| projector.projection.requirements().stream_index)
    {
        return Err(CliError::new(
            Kind::Usage,
            "capture --field cannot select stream indices; save the capture and use read --field",
        ));
    }
    let decoding = Decoding::prepare(
        args.dissect,
        projector.is_some(),
        args.filter.as_deref(),
        &registry,
        limits.snap_length,
    )?;
    // `Decoding` evaluates the same filter itself so a frame is decoded at most once.
    let selector = if decoding.is_none() {
        filtering::optional_frame_selector(args.filter.as_deref(), &registry, limits.snap_length)?
    } else {
        None
    };
    let policy = args.budgets.into_policy();
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
                file_limits(&policy),
            )
        })
        .transpose()
        .map_err(CliError::classified)?;
    let mut seen = HashSet::new();
    let mut interfaces = Vec::new();
    for source in args.interface {
        let interface = resolve(source.get()?)?;
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
    let request = workflow::Request::new(
        net::capture::GroupRequest {
            interfaces,
            limits,
            filter: args.capture_filter,
            promiscuous: args.promiscuous,
            native,
        },
        timeout,
    );
    drive(
        &client(registry, policy, Runtime::Capture),
        request,
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

fn validate_output(args: &Args, format: CaptureFormat) -> Result<Compression, CliError> {
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
    Ok(compression)
}

/// Selection decodes a kept frame once and parks it so emission republishes
/// the same dissection; decoded state never outlives one frame.
struct Decoding {
    frames: FrameDecoder,
    parked: Option<(u64, DecodedPacket)>,
}

impl Decoding {
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
            frames: filtering::frame_decoder(registry, filter, snap_length)?,
            parked: None,
        }))
    }

    fn select(&mut self, source_frame: u64, frame: &Frame) -> Result<bool, CliError> {
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

struct Output<'a> {
    format: CaptureFormat,
    compression: Compression,
    selector: Option<FrameSelector>,
    decoding: Option<Decoding>,
    projector: Option<crate::rendering::Projector>,
    files: Option<Files>,
    stream: &'a StreamEncoder,
}
struct Destinations {
    files: Option<Files>,
    writer: Option<capture_file::Writer<compression::Output<io::Stdout>>>,
    projector: Option<crate::rendering::Projector>,
    format: CaptureFormat,
    compression: Compression,
    limits: capture_file::Limits,
    stream: StreamEncoder,
}

impl Destinations {
    fn start(&mut self, sources: Vec<Source>) -> Result<(), BoundaryError> {
        if let Some(files) = &mut self.files {
            files
                .initialize(sources)
                .map_err(BoundaryError::from_error)?;
        } else if matches!(self.format, CaptureFormat::Pcap | CaptureFormat::PcapNg) {
            let destination = compression::Output::new(io::stdout(), self.compression.format())
                .map_err(BoundaryError::from_error)?;
            self.writer = Some(
                writer::initialize(
                    destination,
                    if self.format == CaptureFormat::Pcap {
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

    fn frame(
        &mut self,
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
        let mut decoding = decoding.map(lock);
        emit_frame(
            decoding.as_deref_mut(),
            self.projector.as_mut(),
            &self.stream,
            self.format,
            &mut self.writer,
            source_frame,
            frame,
        )
        .map_err(CliError::into_boundary_error)?;
        Ok(control)
    }

    /// Finalizes every initialized destination even when capture or a consumer
    /// failed; finalization failures chain behind `error`.
    fn finish(
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

fn file_limits(policy: &Policy) -> capture_file::Limits {
    let budget = CaptureBudget::new(policy);
    capture_file::Limits {
        max_frames: budget.max_frames(),
        max_bytes: budget.max_bytes(),
    }
}

fn drive<P: packetcraftr::CaptureProviders>(
    client: &packetcraftr::Client<P>,
    request: workflow::Request,
    rendering: Output<'_>,
) -> Result<(), CliError> {
    let Output {
        format,
        compression,
        selector,
        decoding,
        projector,
        files,
        stream,
    } = rendering;
    // The selector runs on the capture's thread and the sink on its worker;
    // the capture waits for each answer, so they never contend.
    let decoding = decoding.map(|decoding| Arc::new(Mutex::new(decoding)));
    let destinations = Arc::new(Mutex::new(Destinations {
        files,
        writer: None,
        projector,
        format,
        compression,
        limits: file_limits(client.policy()),
        stream: stream.clone(),
    }));
    let request = match (&decoding, selector) {
        (Some(decoding), _) => {
            let decoding = Arc::clone(decoding);
            request.with_selector(move |number, frame| {
                lock(&decoding)
                    .select(number, frame)
                    .map_err(CliError::into_boundary_error)
            })
        }
        (None, Some(selector)) => request.with_selector(move |number, frame| {
            selector
                .keep(number, frame)
                .map_err(|error| filtering::frame_error(number, error).into_boundary_error())
        }),
        (None, None) => request,
    };
    let sink = {
        let destinations = Arc::clone(&destinations);
        move |event| {
            let mut destinations = lock(&destinations);
            match event {
                Event::Started { sources } => {
                    destinations.start(sources).map(|()| Control::Continue)
                }
                Event::Frame {
                    source_frame,
                    elapsed,
                    frame,
                    ..
                } => destinations.frame(decoding.as_deref(), source_frame, elapsed, frame),
            }
        }
    };
    let result = client.capture(request, sink);
    let (report, error) = match result {
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
    let mut destinations = lock(&destinations);
    let (error, files) = destinations.finish(error);

    let snapshot = output::capture::Snapshot::from((&report, files));
    if let Some(error) = error {
        return Err(error.with_capture(snapshot));
    }
    // A projection that never matched a frame still owes its text header.
    if format == CaptureFormat::Text
        && let Some(projector) = destinations.projector.take()
    {
        projector
            .finish(report.frames_delivered, report.stats.bytes, stream)
            .map_err(|error| error.with_capture(snapshot.clone()))?;
    }
    rendering::render_complete(format, &snapshot, report.diagnostics, stream)
        .map_err(|error| error.with_capture(snapshot))
}

/// A panic in the selector or sink leaves the state as it was, which finalization still needs.
fn lock<T>(state: &Mutex<T>) -> MutexGuard<'_, T> {
    state.lock().unwrap_or_else(PoisonError::into_inner)
}

fn emit_frame(
    decoding: Option<&mut Decoding>,
    projector: Option<&mut crate::rendering::Projector>,
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
                    &core::filter::Context::frame(&decoded, source_frame),
                    projector.remaining(),
                )
                .map_err(CliError::classified)?;
            return projector.emit(source_frame, values, stream);
        }
        return match format {
            CaptureFormat::Text => {
                let stack = output::frame::Stack::from(&decoded);
                let frame =
                    output::frame::Captured::try_from(frame).map_err(CliError::classified)?;
                let source_frame = source_frame.try_into().map_err(CliError::classified)?;
                render_frame_text(source_frame, &frame, Some(&stack))
            }
            CaptureFormat::Ndjson => output::read::Frame::try_from((source_frame, frame, &decoded))
                .map_err(CliError::classified)
                .and_then(|record| stream.emit_data(record, Vec::new()).map_err(Into::into)),
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
        CaptureFormat::Text => output::frame::Captured::try_from(frame)
            .map_err(CliError::classified)
            .and_then(|frame| {
                let source_frame = source_frame.try_into().map_err(CliError::classified)?;
                render_frame_text(source_frame, &frame, None)
            }),
        CaptureFormat::Hex => output::frame::Captured::try_from(frame)
            .map_err(CliError::classified)
            .and_then(|frame| write_hex_line(frame.bytes())),
        CaptureFormat::Ndjson => output::read::Frame::try_from((source_frame, frame))
            .map_err(CliError::classified)
            .and_then(|record| stream.emit_data(record, Vec::new()).map_err(Into::into)),
        CaptureFormat::Json => Ok(()),
        CaptureFormat::Pcap | CaptureFormat::PcapNg => writer::write_frame(
            writer.as_mut().expect("writer initialized before frames"),
            frame,
        )
        .map_err(CliError::classified),
    }
}
