// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! TLS session assembly CLI command.

use crate::output::contract::ToolFormat;

use std::sync::OnceLock;

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
use analysis::tls::{Collector, Limits as TlsLimits, Status};
use rendering::State;

/// Which assembled sessions the command reports.
///
/// Every selector here runs on a finished session rather than on a frame. A
/// frame filter would drop the ServerHello and turn each session into
/// `client_only`, which is why the command has no `--filter` and why only
/// `--stream` — stream-preserving by construction — is pushed down to the
/// frame level.
struct Selector {
    sni: Option<SniPattern>,
    server_port: Option<u16>,
    statuses: Vec<Status>,
}

impl Selector {
    fn matches(&self, session: &analysis::tls::Session) -> bool {
        if let Some(port) = self.server_port
            && session.server_endpoint.port != port
        {
            return false;
        }
        if !self.statuses.is_empty() && !self.statuses.contains(&session.status) {
            return false;
        }
        if let Some(pattern) = &self.sni {
            let name = session
                .client
                .as_ref()
                .and_then(|client| client.sni.as_deref());
            return name.is_some_and(|name| pattern.matches(name));
        }
        true
    }
}

/// A `--sni` pattern: a literal compared case-insensitively, optionally
/// anchored loosely at either end by `*`.
///
/// `*` at the start, the end, or both is the whole vocabulary; it is not a
/// glob dialect.
struct SniPattern {
    literal: String,
    leading: bool,
    trailing: bool,
}

impl SniPattern {
    fn parse(pattern: &str) -> Result<Self, CliError> {
        let (leading, rest) = match pattern.strip_prefix('*') {
            Some(rest) => (true, rest),
            None => (false, pattern),
        };
        let (trailing, literal) = match rest.strip_suffix('*') {
            Some(literal) => (true, literal),
            None => (false, rest),
        };
        if literal.contains('*') {
            return Err(CliError::new(
                Kind::Usage,
                format!(
                    "invalid --sni '{pattern}': '*' is supported only at the start, \
                     the end, or both"
                ),
            ));
        }
        Ok(Self {
            literal: literal.to_lowercase(),
            leading,
            trailing,
        })
    }

    fn matches(&self, name: &str) -> bool {
        let name = name.to_lowercase();
        match (self.leading, self.trailing) {
            (true, true) => name.contains(&self.literal),
            (true, false) => name.ends_with(&self.literal),
            (false, true) => name.starts_with(&self.literal),
            (false, false) => name == self.literal,
        }
    }
}

impl super::Spec for Args {
    type Format = crate::output::contract::ToolFormat;
    const CANCELLATION: bool = true;
    const OFFLINE: bool = true;

    fn publication_duration(&self) -> Option<std::time::Duration> {
        Some(self.limits.duration.max_duration())
    }

    fn resources(&self, settings: &mut crate::resources::Settings<'_>) {
        crate::resources::declare!(settings, self, [
            max_tls_buffer_bytes: Bytes @ ActiveState,
            max_tls_sessions: Count @ ActiveState,
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
    let selected_stream = arguments.stream.map(tcp_stream_index).transpose()?;
    let selector = Selector {
        sni: arguments
            .sni
            .as_deref()
            .map(SniPattern::parse)
            .transpose()?,
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

    // The stream filter narrows reassembly to one conversation while indices
    // stay capture-global, so the index reported is the one asked for.
    let source = selected_stream.map(|index| format!("tcp.stream == {index}"));
    let prepared = prepare(arguments.limits, source.as_deref(), &arguments.decode)?;
    // Assembly consumes the reassembler's in-order deliveries; the session
    // raises the pipeline flags from the collector's declared needs.
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

    let run_summary = outcome.run;
    let summary = output::tls::Summary::from_analysis(
        outcome.summary,
        run_summary.frames_read,
        run_summary.frames_matched,
        state.counts(),
        &run_summary.ip_reassembly,
    );
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
    static REASON: OnceLock<String> = OnceLock::new();
    let reason = REASON.get_or_init(|| {
        format!(
            "cannot be below the per-direction handshake buffer of {} bytes",
            analysis::tls::MAX_DIRECTION_BUFFER
        )
    });
    CliError::classified(analysis::Error::InvalidLimit {
        field: "--max-tls-buffer-bytes",
        value: u64::try_from(value).unwrap_or(u64::MAX),
        reason,
    })
}

/// The TCP index `--stream` selects, rejecting the transports this command
/// cannot assemble.
fn tcp_stream_index(selected: analysis::StreamRef) -> Result<u64, CliError> {
    match selected.transport {
        StreamTransport::Tcp => Ok(selected.index),
        StreamTransport::Udp => Err(CliError::new(
            Kind::Usage,
            format!(
                "invalid --stream '{}:{}': TLS sessions are assembled from TCP streams only; \
                 UDP port 443 is QUIC, which this command does not read",
                selected.transport, selected.index
            ),
        )),
    }
}
