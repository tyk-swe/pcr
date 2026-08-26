// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! TLS session assembly CLI command.

pub(super) mod arguments;
mod rendering;

use packetcraftr::{analysis, output};

use self::arguments::Args;
use super::super::errors::CliError;
use super::super::input::open_capture;
use super::offline_analysis::{
    Prepared, StreamSelector, parse_stream_selector, prepare_with_tls_ports,
};
use crate::rendering::NdjsonStream;

use analysis::expert::StreamTransport;
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
/// Deliberately not a glob dialect. `*` at the start, the end, or both is the
/// whole vocabulary, so the pattern means the same thing here as it does in a
/// shell prompt and there is nothing else to learn.
struct SniPattern {
    literal: String,
    leading: bool,
    trailing: bool,
}

impl SniPattern {
    fn parse(pattern: &str) -> Result<Self, CliError> {
        let leading = pattern.starts_with('*');
        let rest = if leading { &pattern[1..] } else { pattern };
        let trailing = rest.ends_with('*');
        let literal = rest.strip_suffix('*').unwrap_or(rest);
        if literal.contains('*') {
            return Err(CliError::new(
                2,
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

pub(super) fn run(
    arguments: Args,
    format: output::contract::Format,
    stream: &mut NdjsonStream,
) -> Result<(), CliError> {
    let selected_stream = arguments
        .stream
        .as_deref()
        .map(parse_tcp_stream_selector)
        .transpose()?;
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
        ..TlsLimits::default()
    };
    if arguments.max_tls_buffer_bytes != 0
        && arguments.max_tls_buffer_bytes < analysis::tls::MAX_DIRECTION_BUFFER
    {
        return Err(buffer_floor_error(arguments.max_tls_buffer_bytes));
    }
    tls_limits.validate().map_err(CliError::classified)?;

    // The stream filter narrows reassembly to one conversation while indices
    // stay capture-global, so the index reported is the one asked for.
    let source = selected_stream.map(|index| format!("tcp.stream == {index}"));
    let Prepared {
        registry,
        filter,
        limits,
    } = prepare_with_tls_ports(
        arguments.limits,
        source.as_deref(),
        &arguments.tls_ports.ports,
    )?;
    let mut reader = open_capture(&arguments.path, arguments.limits.capture)?;

    let options = analysis::Options {
        filter: filter.as_ref(),
        // Assembly consumes the reassembler's in-order deliveries.
        tcp_events: true,
        limits,
    };
    let mut collector = Collector::new(tls_limits);
    let mut state = State::new(arguments.max_tls_sessions);
    let run_summary = analysis::run(&mut reader, registry, &options, |record| {
        for event in collector.observe(&record) {
            if selector.matches(&event.session) {
                rendering::render_session(format, event.session, &mut state, stream)
                    .map_err(CliError::into_boundary_error)?;
            }
        }
        Ok(())
    })
    .map_err(CliError::classified)?;
    let (trailing, summary) = collector.finish(&run_summary.trailing_tcp_events);
    for event in trailing {
        if selector.matches(&event.session) {
            rendering::render_session(format, event.session, &mut state, stream)?;
        }
    }

    // A selector that matched no frame at all is more likely a typo than an
    // empty conversation, so the range that does exist is worth the reread.
    if let Some(index) = selected_stream
        && run_summary.frames_matched == 0
    {
        return Err(missing_stream_error(index, &arguments)?);
    }

    let summary = output::tls::Summary::from_analysis(
        summary,
        run_summary.frames_read,
        run_summary.frames_matched,
        state.counts(),
    );
    match format {
        output::contract::Format::Text => {
            rendering::render_text(&state, &summary, &arguments.tls_ports.ports)
        }
        output::contract::Format::Json => rendering::render_aggregate(state, summary),
        output::contract::Format::Ndjson => rendering::render_stream(summary, stream),
        _ => unreachable!("the format contract admits only text, json, and ndjson"),
    }
}

/// Rejects a whole-run buffer ceiling that one direction alone could fill.
///
/// The core check reports this as `max_direction_bytes`, an internal field no
/// flag sets, so the flag that did set it is named here instead.
fn buffer_floor_error(value: usize) -> CliError {
    CliError::classified(analysis::Error::InvalidLimit {
        field: "--max-tls-buffer-bytes",
        value: u64::try_from(value).unwrap_or(u64::MAX),
        reason: "cannot be below the per-direction handshake buffer of 135168 bytes",
    })
}

/// Parses `--stream`, rejecting the transports this command cannot assemble.
fn parse_tcp_stream_selector(spec: &str) -> Result<u64, CliError> {
    let StreamSelector { transport, index } = parse_stream_selector(spec)?;
    match transport {
        StreamTransport::Tcp => Ok(index),
        StreamTransport::Udp => Err(CliError::new(
            2,
            format!(
                "invalid --stream '{spec}': TLS sessions are assembled from TCP streams only; \
                 UDP port 443 is QUIC, which this command does not read"
            ),
        )),
    }
}

/// Reports which TCP conversations the capture actually holds.
///
/// Only reached when the selector matched nothing, so the second read costs
/// nothing on the path that works.
fn missing_stream_error(index: u64, arguments: &Args) -> Result<CliError, CliError> {
    let streams = count_tcp_streams(arguments)?;
    Ok(CliError::new(
        2,
        match streams {
            0 => format!("--stream tcp:{index} is not present (the capture has no TCP streams)"),
            count => format!("--stream tcp:{index} is not present (0..{count})"),
        },
    ))
}

/// Counts the capture's TCP conversations, which are indexed before filtering.
fn count_tcp_streams(arguments: &Args) -> Result<u64, CliError> {
    let Prepared {
        registry, limits, ..
    } = prepare_with_tls_ports(arguments.limits, None, &arguments.tls_ports.ports)?;
    let mut reader = open_capture(&arguments.path, arguments.limits.capture)?;
    let options = analysis::Options {
        filter: None,
        tcp_events: false,
        limits,
    };
    let mut highest = None;
    analysis::run(&mut reader, registry, &options, |record| {
        if let Some(stream) = record.tcp_stream {
            highest = Some(highest.map_or(stream, |seen: u64| seen.max(stream)));
        }
        Ok(())
    })
    .map_err(CliError::classified)?;
    Ok(highest.map_or(0, |highest| highest.saturating_add(1)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_buffer_floor_error_quotes_the_per_direction_buffer() {
        let error = buffer_floor_error(1_024);
        assert_eq!(error.exit_code, 2);
        assert!(
            error.message.contains("--max-tls-buffer-bytes=1024"),
            "{}",
            error.message
        );
        assert!(
            error
                .message
                .contains(&analysis::tls::MAX_DIRECTION_BUFFER.to_string()),
            "{}",
            error.message
        );
    }
}
