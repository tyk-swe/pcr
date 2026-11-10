pub(crate) mod arguments;
mod keylog;
mod live;
mod output;
mod rendering;
mod write;

use crate::command_options::{AnalysisStages, Bounded as _};
use crate::publication::emit_published;
use crate::terminal::write_stdout_line;
use crate::{
    commands,
    errors::CliError,
    invocation::Invocation,
    output::{
        contract::{Command, Format},
        envelope::Published,
    },
    resources::Settings,
};
use arguments::Args;
use packetcraftr_core::{
    analysis::{self, quic},
    budget::Deadline,
    error::{BoundaryError, Kind},
};

impl commands::Spec for Args {
    const PUBLISHED: &'static [crate::output::contract::PublishedType] = &[
        crate::output::contract::PublishedType {
            definition: "quicSuccess",
            command: "quic",
            rust_types: &["crate::commands::analyze::quic::output::Report"],
            events: &[],
            example: "examples/documents/quic.json",
        },
        crate::output::contract::PublishedType {
            definition: "quicStreamSuccess",
            command: "quic",
            rust_types: &["crate::commands::analyze::quic::output::Event"],
            events: &["complete", "connection", "stream_data"],
            example: "examples/documents/quic-event.json",
        },
    ];
    const FORMATS: &'static [Format] = &[Format::Text, Format::Json, Format::Ndjson];
    const CANCELLATION: bool = true;
    fn run_time(&self) -> Option<&dyn crate::command_options::Bounded> {
        Some(&self.limits)
    }
    fn resources(&self, settings: &mut Settings<'_>) {
        crate::resources::declare!(settings,self,[
            max_connections:Count @ ActiveState,
            max_quic_buffered_bytes:Bytes @ ActiveState,
            max_quic_stream_bytes:Bytes @ ActiveState,
            max_pending_packets:Count @ ActiveState,
            max_quic_streams:Count @ ActiveState,
            quic_idle_expiry_ms:Milliseconds @ ActiveState,
            max_output_connections:Count @ ResultRetention,
            max_application_output_bytes:Bytes @ ResultRetention,
        ]);

        self.limits.resources(
            settings,
            AnalysisStages {
                tcp: false,
                index: crate::resources::Enabled::Fixed(true),
                provenance: true,
            },
        );
        if !self.interface.is_empty() {
            self.timeout.resources(settings);
            self.capture.resources(settings);
        }
    }
    fn run(self, invocation: &Invocation) -> Result<commands::CommandExit, CliError> {
        run(self, invocation).map(|()| commands::CommandExit::SUCCESS)
    }
}

fn run(args: Args, invocation: &Invocation) -> Result<(), CliError> {
    let limits = args.quic_limits();
    limits.validate().map_err(CliError::classified)?;
    if args.max_output_connections == 0 || args.max_application_output_bytes == 0 {
        return Err(CliError::new(
            Kind::Usage,
            "QUIC output limits must be non-zero",
        ));
    }
    if args.path.is_some() && (args.capture_filter.is_some() || args.promiscuous) {
        return Err(CliError::new(
            Kind::Usage,
            "--capture-filter and --promiscuous require --interface",
        ));
    }
    let setup =
        commands::offline_analysis::prepare(args.limits, args.filter.as_deref(), &args.decode)?;
    let mut collector = quic::Collector::new(limits).map_err(CliError::classified)?;
    let mut state = rendering::State::new(&args, invocation)?;
    let mut secrets = keylog::Input::open(args.keylog.as_deref())?;
    secrets.poll(&mut collector, invocation, args.path.is_some())?;
    let encoder = &invocation.output;
    let (run, capture, collector, secrets, state) = if let Some(path) = &args.path {
        let mut reader = crate::input::open_capture(
            &invocation.control,
            &invocation.output,
            path,
            setup.capture_limits,
        )?;
        let mut options = setup.options(invocation);
        options.track_sources = true;
        let run = analysis::run(&mut reader, setup.registry.clone(), &options, |record| {
            for event in collector
                .observe(&record)
                .map_err(BoundaryError::from_error)?
            {
                state
                    .event(event, &args, invocation, encoder)
                    .map_err(CliError::into_boundary_error)?;
            }
            Ok(())
        })
        .map_err(CliError::classified)?;
        (run, None, collector, secrets, state)
    } else {
        let live = live::run(&args, &setup, collector, secrets, state, invocation)?;
        (
            live.run,
            Some(live.capture),
            live.collector,
            live.secrets,
            live.state,
        )
    };
    finish(&args, invocation, run, capture, collector, secrets, state)
}

fn finish(
    args: &Args,
    invocation: &Invocation,
    run: analysis::Summary,
    capture: Option<crate::output::capture::Snapshot>,
    mut collector: quic::Collector,
    mut secrets: keylog::Input,
    mut state: rendering::State,
) -> Result<(), CliError> {
    let snapshot = capture.clone();
    let result = (|| {
        let encoder = &invocation.output;
        secrets.poll(&mut collector, invocation, true)?;
        let owned_deadline;
        let deadline = if let Some(deadline) = &invocation.control.deadline {
            deadline.as_ref()
        } else {
            owned_deadline = Deadline::new(args.limits.max_duration());
            &owned_deadline
        };
        let input_incomplete = run.input_incomplete()
            || capture.as_ref().is_some_and(|capture| {
                !capture.summary.capture_statistics_complete
                    || capture.summary.sources.iter().any(|source| {
                        source.statistics.dropped_frames > 0
                            || source.statistics.receiver_dropped_frames > 0
                            || source.statistics.overflow_events > 0
                    })
            });
        if input_incomplete {
            collector.mark_capture_incomplete();
            state.mark_capture_incomplete();
        }
        let engine = collector
            .finish(deadline, |event| {
                state
                    .event(event, args, invocation, encoder)
                    .map_err(CliError::into_boundary_error)
            })
            .map_err(CliError::classified)?;
        if (args.connection.is_some() || args.stream.is_some()) && state.selected == 0 {
            return Err(CliError::new(
                Kind::Usage,
                "no QUIC connection or stream matched the selectors",
            ));
        }
        state.publish()?;
        let summary = output::Summary {
            engine: engine.into(),
            frames_read: run.frames_read,
            frames_matched: run.frames_matched,
            bytes_read: run.bytes_read,
            clock: run.clock.into(),
            ip_reassembly: (&run.ip_reassembly).into(),
            incomplete_sources: run.incomplete_sources.len() as u64,
            source_outcomes_omitted: run.source_outcomes_omitted,
            input_incomplete,
            connections_selected: state.selected,
            connections_omitted: state.omitted,
            application_output_bytes: state.output_bytes,
        };
        match invocation.format {
            Format::Text => write_stdout_line(
                invocation,
                format_args!(
                    "QUIC connections={} selected={} packets={} decrypted={} unassociated={} malformed={} evictions={} rejected_keys={} input_incomplete={}",
                    summary.engine.connections,
                    summary.connections_selected,
                    summary.engine.packets,
                    summary.engine.decrypted_packets,
                    summary.engine.unassociated_packets,
                    summary.engine.malformed_datagrams,
                    summary.engine.connections_evicted,
                    summary.engine.keylog_records_rejected,
                    summary.input_incomplete
                ),
            ),
            Format::Json => emit_published(
                invocation,
                Command::Quic,
                Published::new(
                    output::Report {
                        connections: state.retained,
                        summary,
                        capture,
                    },
                    Vec::new(),
                ),
            ),
            Format::Ndjson => Ok(encoder.complete_published(Published::new(
                output::Event::Complete {
                    summary: Box::new(summary),
                    capture: capture.map(Box::new),
                },
                Vec::new(),
            ))?),
            other => other.unreachable(),
        }
    })();
    result.map_err(|error: CliError| match snapshot {
        Some(capture) => error.with_capture(capture),
        None => error,
    })
}
