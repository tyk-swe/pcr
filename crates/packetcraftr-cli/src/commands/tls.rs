// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! TLS session assembly CLI command.

use crate::output::contract::ToolFormat;

use packetcraftr_core::error::Kind;

pub(super) mod arguments;
mod rendering;

use packetcraftr_core::analysis;

use crate::output;

use self::arguments::Args;
use super::offline_analysis::prepare;
use crate::errors::CliError;
use crate::input::open_capture;
use crate::rendering::StreamEncoder;

use analysis::StreamTransport;
use analysis::tls::{Collector, Limits as TlsLimits, Selector, SniPattern, Status};
use rendering::State;

impl super::Spec for Args {
    type Format = crate::output::contract::ToolFormat;
    const CANCELLATION: bool = true;
    const OFFLINE: bool = true;

    fn run_time(&self) -> Option<&dyn crate::command_options::Bounded> {
        Some(&self.limits)
    }

    fn resources(&self, settings: &mut crate::resources::Settings<'_>) {
        crate::resources::declare!(settings, self, [
            max_tls_buffer_bytes: Bytes @ ActiveState preset(4194304, 33554432),
            max_tls_sessions: Count @ ActiveState preset(128, 2048),
            max_output_sessions: Count @ ResultRetention,
        ]);
        self.limits.resources(
            settings,
            crate::command_options::AnalysisStages::with_tcp(true),
        );
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
    format: ToolFormat,
    stream: &StreamEncoder,
) -> Result<(), CliError> {
    let selected_stream = arguments
        .stream
        .as_ref()
        .map(tcp_stream_index)
        .transpose()?;
    // Selection runs on finished sessions: a frame filter would drop the
    // ServerHello and turn each session into `client_only`, which is why the
    // command has no `--filter` and only `--stream` narrows the frames.
    let selector = Selector {
        sni: arguments.sni.as_deref().map(sni_pattern).transpose()?,
        server_port: arguments.server_port,
        statuses: arguments
            .statuses
            .iter()
            .copied()
            .map(Status::from)
            .collect(),
    };
    let tls_limits = TlsLimits {
        max_sessions: arguments.max_tls_sessions,
        max_buffered_bytes: arguments.max_tls_buffer_bytes,
    };
    if arguments.max_tls_buffer_bytes < analysis::tls::MAX_DIRECTION_BUFFER {
        return Err(buffer_floor_error(arguments.max_tls_buffer_bytes));
    }
    let collector = Collector::new(tls_limits).map_err(CliError::classified)?;

    let prepared = prepare(arguments.limits, None, &arguments.decode)?;
    // Assembly consumes the reassembler's in-order deliveries; the session
    // raises the pipeline flags from the collector's declared needs. The
    // stream selector narrows reassembly to one conversation while indices
    // stay capture-global, so the index reported is the one asked for.
    let session = analysis::Session::new(
        prepared.registry.clone(),
        prepared.options(),
        collector,
        selected_stream.map(|index| analysis::StreamRef {
            transport: StreamTransport::Tcp,
            index,
        }),
    );
    let mut reader = open_capture(&arguments.path, arguments.limits.capture.reader)?;

    let mut state = State::new(arguments.max_output_sessions);
    let outcome = session
        .run(
            &mut reader,
            super::offline_analysis::ip_event_sink(format, stream),
            |event| {
                if selector.matches(&event.session) {
                    rendering::render_session(format, event.session, &mut state, stream)
                        .map_err(CliError::into_boundary_error)?;
                }
                Ok(())
            },
        )
        .map_err(CliError::classified)?;

    // Stream indices are assigned before filtering, so no matched frame
    // means the requested conversation is absent.
    if let Some(index) = selected_stream
        && outcome.selected_absent()
    {
        return Err(CliError::new(
            Kind::Usage,
            format!("--stream tcp:{index} is not present"),
        ));
    }

    let (selected, omitted) = state.counts();
    let summary = output::tls::Summary::from((outcome.summary, &outcome.run, selected, omitted));
    match format {
        ToolFormat::Text => rendering::render_text(&state, &summary, &prepared.registry),
        ToolFormat::Json => rendering::render_aggregate(state, summary),
        ToolFormat::Ndjson => rendering::render_stream(summary, stream),
    }
}

/// Rejects a whole-run buffer ceiling that one direction alone could fill.
///
/// The per-direction buffer is a core constant rather than a limit any flag
/// sets, so the error names the flag that set the ceiling instead.
fn buffer_floor_error(value: usize) -> CliError {
    CliError::classified(analysis::Error::InvalidLimit {
        field: "--max-tls-buffer-bytes",
        value: u64::try_from(value).unwrap_or(u64::MAX),
        reason: analysis::Constraint::AtLeastTlsDirectionBuffer,
    })
}

/// The `--sni` pattern, refused in the option's own words.
fn sni_pattern(pattern: &str) -> Result<SniPattern, CliError> {
    pattern.parse().map_err(|error: analysis::Error| {
        CliError::refused_option(
            format!(
                "invalid --sni '{pattern}': '*' is supported only at the start, \
                 the end, or both"
            ),
            &error,
        )
    })
}

/// The TCP index `--stream` selects, rejecting the transports this command
/// cannot assemble.
fn tcp_stream_index(
    selector: &crate::command_options::Selector<analysis::StreamRef>,
) -> Result<u64, CliError> {
    let selected = selector.get()?;
    match selected.transport {
        StreamTransport::Tcp => Ok(selected.index),
        StreamTransport::Udp => Err(CliError::new(
            Kind::Usage,
            format!(
                "invalid --stream '{}': TLS sessions are assembled from TCP streams only; \
                 UDP port 443 is QUIC, which this command does not read",
                selector.text()
            ),
        )),
    }
}
