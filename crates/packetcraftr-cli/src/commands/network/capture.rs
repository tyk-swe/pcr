// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

pub(in crate::commands) mod arguments;
mod files;
mod frames;
mod rendering;

mod writer;

use self::arguments::Args;
use crate::output::{
    capture::Retention,
    contract::{Command, Format},
};
use crate::{
    errors::CliError,
    filtering,
    invocation::StreamEncoder,
    system::{Runtime, client, resolve},
};
use packetcraftr_core::{capture_file, error::Kind};
use packetcraftr_netio as net;
use std::{
    collections::HashSet,
    time::{Duration, Instant},
};

use self::files::Files;
use self::frames::{Decoding, Destinations};
use crate::command_options::Compression;
use crate::output;
use crate::rendering::FieldTree;
use packetcraftr::capture::{self as workflow, Control, Event};
use packetcraftr::policy::{CaptureBudget, Policy};
use packetcraftr_core::error::Classified;
use packetcraftr_core::filter::FrameSelector;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

impl crate::commands::Spec for Args {
    const FORMATS: &'static [crate::output::contract::Format] = &[
        crate::output::contract::Format::Text,
        crate::output::contract::Format::Json,
        crate::output::contract::Format::Ndjson,
        crate::output::contract::Format::Hex,
        crate::output::contract::Format::Pcap,
        crate::output::contract::Format::PcapNg,
    ];
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
        self.tree.resources(settings);
    }

    fn run(
        self,
        invocation: &crate::invocation::Invocation,
    ) -> Result<crate::commands::CommandExit, CliError> {
        let format = invocation.format;
        let stream = &invocation.output;
        run(invocation, self, format, stream).map(|()| crate::commands::CommandExit::SUCCESS)
    }
}

pub(super) fn run(
    invocation: &crate::invocation::Invocation,
    args: Args,
    format: Format,
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
        format,
    )?;
    if projector
        .as_ref()
        .is_some_and(|projector| projector.projection.requirements().stream_index)
    {
        return Err(CliError::new(
            Kind::Usage,
            "capture --field cannot select stream indices; save the capture and use packetcraftr files read --field",
        ));
    }
    let mut decoding = Decoding::prepare(
        args.dissect,
        projector.is_some(),
        args.filter.as_deref(),
        &registry,
        limits.snap_length,
    )?;
    if let Some(decoding) = decoding.as_mut() {
        decoding.tree = args
            .tree
            .tree
            .then(|| FieldTree::new(Arc::clone(&registry), args.tree.max_tree_bytes));
    }
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
        let interface = resolve(invocation, source.get()?)?;
        if seen.insert(interface.index) {
            interfaces.push(interface);
        }
    }
    if format == Format::Pcap && interfaces.len() != 1 {
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
        invocation,
        &client(invocation, registry, policy, Runtime::Capture),
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

fn validate_output(args: &Args, format: Format) -> Result<Compression, CliError> {
    let compression = if args.write.is_some() {
        if !matches!(format, Format::Text | Format::Json | Format::Ndjson) {
            return Err(CliError::new(
                Kind::Usage,
                "--write requires text, JSON, or NDJSON reporting",
            ));
        }
        args.compression.for_file()
    } else {
        let compression = args.compression.for_output(format)?;
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
        if format == Format::Json {
            return Err(CliError::new(
                Kind::Usage,
                "JSON capture summaries require --write to retain packet data",
            ));
        }
        compression
    };
    if args.tree.tree && !args.dissect {
        return Err(CliError::from_classification(
            packetcraftr_core::error::Classification::new(
                "cli.tree_requires_dissect",
                Kind::Usage,
                Some("add --dissect to show each frame's layers as a tree"),
            ),
            "--tree requires --dissect",
            Vec::new(),
        ));
    }
    args.tree.validate_format(format == Format::Text, format)?;
    if (args.dissect || !args.fields.is_empty()) && !matches!(format, Format::Text | Format::Ndjson)
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

struct Output<'a> {
    format: Format,
    compression: Compression,
    selector: Option<FrameSelector>,
    decoding: Option<Decoding>,
    projector: Option<crate::rendering::Projector>,
    files: Option<Files>,
    stream: &'a StreamEncoder,
}
fn file_limits(policy: &Policy) -> capture_file::Limits {
    let budget = CaptureBudget::new(policy);
    capture_file::Limits {
        max_frames: budget.max_frames(),
        max_bytes: budget.max_bytes(),
    }
}

fn drive<P: packetcraftr::CaptureProviders>(
    invocation: &crate::invocation::Invocation,
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
        let invocation = invocation.clone();
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
                } => destinations.frame(
                    &invocation,
                    decoding.as_deref(),
                    source_frame,
                    elapsed,
                    frame,
                ),
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
    if format == Format::Text
        && let Some(projector) = destinations.projector.take()
    {
        projector
            .finish(
                invocation,
                report.frames_delivered,
                report.stats.bytes,
                stream,
            )
            .map_err(|error| error.with_capture(snapshot.clone()))?;
    }
    rendering::render_complete(invocation, format, &snapshot, report.diagnostics, stream)
        .map_err(|error| error.with_capture(snapshot))
}

/// A panic in the selector or sink leaves the state as it was, which finalization still needs.
fn lock<T>(state: &Mutex<T>) -> MutexGuard<'_, T> {
    state.lock().unwrap_or_else(PoisonError::into_inner)
}
