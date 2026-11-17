// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

mod output;
mod rendering;

use std::path::PathBuf;

use packetcraftr_core::{
    analysis::{self, http3, quic},
    budget::Deadline,
    error::{BoundaryError, Kind},
};

use crate::command_options::{AnalysisStages, DecodeArgs, OfflineLimitsArgs, OutputBytes};
use crate::commands::{CommandExit, Spec, offline_analysis};
use crate::errors::CliError;
use crate::invocation::Invocation;
use crate::output::contract::{Command, Format, PublishedType};
use crate::resources::{Enabled, Settings};

use super::quic::{arguments::StreamRetentionArgs, keylog};
use output::{Event, Report, Summary, Terminal};

#[derive(Debug, clap::Args)]
pub(crate) struct Args {
    #[arg(help = "PCAP/PCAPNG input; - reads redirected stdin. gzip and Zstd are detected.")]
    path: PathBuf,
    #[arg(
        long,
        value_name = "PATH",
        help = "NSS TLS key log for the captured QUIC connections"
    )]
    keylog: PathBuf,
    #[arg(
        long,
        value_name = "EXPR",
        help = "Display filter applied after IP reconstruction"
    )]
    filter: Option<String>,
    #[arg(long, help = "Select a capture-global QUIC connection index")]
    connection: Option<u64>,
    #[arg(long, help = "Select a client-initiated bidirectional QUIC stream ID")]
    stream: Option<u64>,
    #[arg(
        long,
        help = "Include decoded header values, which can contain sensitive information"
    )]
    include_header_values: bool,
    #[arg(long, default_value_t = 64 * 1024 * 1024, help = "Maximum serialized HTTP/3 evidence bytes")]
    max_application_output_bytes: usize,
    #[command(flatten)]
    stream_retention: StreamRetentionArgs,
    #[command(flatten)]
    decode: DecodeArgs,
    #[command(flatten)]
    limits: OfflineLimitsArgs,
}

impl Spec for Args {
    const OFFLINE: bool = true;
    const FORMATS: &'static [Format] = crate::output::contract::TEXT_JSON_NDJSON;
    const PUBLISHED: &'static [PublishedType] = &[
        PublishedType {
            definition: "http3Success",
            command: "http3",
            rust_types: &["crate::commands::analyze::http3::output::Report"],
            events: &[],
            example: "examples/documents/http3.json",
        },
        PublishedType {
            definition: "http3StreamSuccess",
            command: "http3",
            rust_types: &[
                "crate::commands::analyze::http3::output::Event",
                "crate::commands::analyze::http3::output::Terminal",
            ],
            events: &["complete", "http3_connection", "http3_exchange"],
            example: "examples/documents/http3-event.json",
        },
    ];

    fn run_time(&self) -> Option<&dyn crate::command_options::Bounded> {
        Some(&self.limits)
    }

    fn resources(&self, settings: &mut Settings<'_>) {
        crate::resources::declare!(settings, self, [
            max_application_output_bytes: Bytes @ ResultRetention preset(8388608, 67108864),
        ]);
        self.stream_retention.resources(settings);
        self.limits.resources(
            settings,
            AnalysisStages {
                tcp: false,
                index: Enabled::Fixed(true),
                provenance: true,
            },
        );
    }

    fn run(self, invocation: &Invocation) -> Result<CommandExit, CliError> {
        run(&self, invocation).map(|()| CommandExit::SUCCESS)
    }
}

fn run(args: &Args, invocation: &Invocation) -> Result<(), CliError> {
    if args.stream.is_some_and(|id| id % 4 != 0 || id >= 1 << 62) {
        return Err(CliError::new(
            Kind::Usage,
            "HTTP/3 requires a client-initiated bidirectional QUIC stream ID",
        ));
    }
    let budget = OutputBytes::new(
        args.max_application_output_bytes,
        "--max-application-output-bytes",
    )?;
    let setup = offline_analysis::prepare(args.limits, args.filter.as_deref(), &args.decode)?;
    let deadline = invocation.control.io_control();
    let quic_limits = quic::Limits {
        max_stream_bytes: args.stream_retention.max_quic_stream_bytes,
        ..quic::Limits::default()
    };
    let mut collector = quic::Collector::new(quic_limits).map_err(CliError::classified)?;
    keylog::Input::open(Some(&args.keylog))?.poll(&mut collector, invocation, true)?;
    let mut reader = setup.open(invocation, &args.path)?;
    let mut options = setup.options(invocation);
    options.track_sources = true;
    let mut state = State {
        args,
        deadline: &deadline,
        output: offline_analysis::EventOutput::new(invocation, budget.get()),
        retained: Vec::new(),
        summary: Summary::default(),
    };
    let run = analysis::run(&mut reader, setup.registry.clone(), &options, |record| {
        for event in collector
            .observe(&record)
            .map_err(BoundaryError::from_error)?
        {
            state.observe(event)?;
        }
        Ok(())
    })
    .map_err(CliError::classified)?;
    let transport = collector
        .finish(&deadline, |event| state.observe(event))
        .map_err(CliError::classified)?;

    if (args.connection.is_some() || args.stream.is_some()) && state.summary.connections == 0 {
        return Err(CliError::new(
            Kind::Usage,
            "selected HTTP/3 connection or stream is not present",
        ));
    }
    state.summary.frames_read = run.frames_read;
    state.summary.input_incomplete = run.input_incomplete();
    state.summary.quic_limit_hits = transport.buffer_limit_hits;
    state.summary.quic_evictions = transport.connections_evicted;
    state.summary.quic_unassociated_packets = transport.unassociated_packets;
    state.summary.keylog_records_rejected = transport.keylog_records_rejected;
    offline_analysis::complete_application(
        invocation,
        Command::Http3,
        Terminal {
            summary: state.summary,
        },
        |terminal| Report::new(state.retained, terminal.summary),
        rendering::summary,
    )
}

struct State<'a> {
    args: &'a Args,
    deadline: &'a Deadline,
    output: offline_analysis::EventOutput<'a>,
    retained: Vec<Event>,
    summary: Summary,
}

impl State<'_> {
    fn observe(&mut self, event: quic::Event) -> Result<(), BoundaryError> {
        let quic::Event::Connection { connection } = event;
        if self
            .args
            .connection
            .is_some_and(|id| id != connection.connection)
        {
            return Ok(());
        }
        match connection.negotiated_alpn.as_deref() {
            None => self.summary.unknown_alpn += 1,
            Some("h3") => {
                let has_stream = |id| {
                    connection
                        .streams
                        .iter()
                        .any(|stream| stream.id == id && !stream.early_data)
                };
                if self.args.stream.is_some_and(|id| !has_stream(id)) {
                    return Ok(());
                }
                http3::inspect(
                    &connection,
                    self.args.stream,
                    http3::Limits::default(),
                    self.deadline,
                    &mut |event| self.publish(event).map_err(CliError::into_boundary_error),
                )?;
            }
            Some(_) => self.summary.skipped_alpn += 1,
        }
        Ok(())
    }

    fn publish(&mut self, event: http3::Event<'_>) -> Result<(), CliError> {
        let event = match event {
            http3::Event::Connection(connection) => {
                self.summary.connections += 1;
                Event::Connection {
                    connection: Box::new(connection.try_into().map_err(CliError::classified)?),
                }
            }
            http3::Event::Exchange(exchange) => {
                self.summary.exchanges += 1;
                Event::Exchange {
                    exchange: Box::new(output::Exchange::new(
                        exchange,
                        self.args.include_header_values,
                    )),
                }
            }
        };
        self.output
            .emit(event, &mut self.retained, rendering::event)
    }
}
