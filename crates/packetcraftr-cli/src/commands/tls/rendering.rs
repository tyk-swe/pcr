// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::fmt::Write as _;

use crate::output::contract::Format;

use packetcraftr_core as core;
use packetcraftr_core::analysis;

use crate::output;

use crate::errors::CliError;
use crate::rendering::Retained;
use crate::rendering::{
    StreamEncoder, comma_separated, duration_text, emit_aggregate, encapsulation_text,
    optional_display, write_stdout_line,
};

use analysis::tls::{ALERT_LEVEL_FATAL, ALERT_LEVEL_WARNING};
use output::tls::{Client, Server, Session, Summary};

pub(super) struct State {
    retained: Retained<Session>,
    selected: u64,
}

impl State {
    pub(super) const fn new(max_sessions: usize) -> Self {
        Self {
            retained: Retained::new(max_sessions),
            selected: 0,
        }
    }

    pub(super) const fn counts(&self) -> (u64, u64) {
        (self.selected, self.retained.omitted())
    }

    fn select(&mut self) {
        self.selected = self.selected.saturating_add(1);
    }
}

pub(super) fn render_session(
    format: Format,
    session: analysis::tls::Session,
    state: &mut State,
    stream: &StreamEncoder,
) -> Result<(), CliError> {
    state.select();
    let session = Session::try_from(session).map_err(CliError::classified)?;
    match format {
        Format::Text => write_stdout_line(format_args!("{}", session_line(&session))),
        Format::Json => {
            state.retained.push(|| session);
            Ok(())
        }
        Format::Ndjson => Ok(stream.emit_data(output::tls::Event::from(session), Vec::new())?),
        other => other.unreachable(),
    }
}

pub(super) fn render_text(
    state: &State,
    summary: &Summary,
    registry: &core::registry::Registry,
) -> Result<(), CliError> {
    if state.selected == 0 {
        match unmatched_note(summary) {
            Some(note) => write_stdout_line(format_args!("{note}"))?,
            None => render_empty(summary, registry)?,
        }
    }
    write_stdout_line(format_args!(
        "{} clock_regressions={} max_rollback={} max_forward_step={}",
        summary_line(summary),
        summary.clock.regressions,
        duration_text(summary.clock.max_regression),
        duration_text(summary.clock.max_forward_step)
    ))
}

pub(super) fn render_aggregate(state: State, summary: Summary) -> Result<(), CliError> {
    emit_aggregate(
        output::contract::Command::Tls,
        output::tls::Report::from((state.retained.into_items(), summary)),
        Vec::new(),
    )
}

pub(super) fn render_stream(summary: Summary, stream: &StreamEncoder) -> Result<(), CliError> {
    Ok(stream.complete(output::tls::Event::from(summary), Vec::new())?)
}

fn unmatched_note(summary: &Summary) -> Option<String> {
    (summary.sessions > 0).then(|| {
        format!(
            "no session matched the selectors ({} assembled)",
            summary.sessions
        )
    })
}

fn render_empty(summary: &Summary, registry: &core::registry::Registry) -> Result<(), CliError> {
    write_stdout_line(format_args!(
        "no TLS sessions assembled: {} frame(s) read, {} matched, {} TCP conversation(s)",
        summary.frames_read, summary.frames_matched, summary.tcp_streams,
    ))?;
    let mut ports: Vec<u16> = registry
        .parent_bindings("tls")
        .into_iter()
        .filter(|(parent, _)| parent.as_str() == "tcp")
        .filter_map(|(_, port)| u16::try_from(port.0).ok())
        .collect();
    ports.sort_unstable();
    ports.dedup();
    write_stdout_line(format_args!(
        "session assembly reads every TCP stream, so a handshake on any port is found; \
         the per-frame tls layer is bound to ports {} (add --tls-port PORT for another)",
        comma_separated(&ports)
    ))?;
    if summary.udp_443_frames > 0 {
        write_stdout_line(format_args!(
            "note: {} UDP frame(s) on port 443 are most likely QUIC, whose handshake this command does not read",
            summary.udp_443_frames
        ))?;
    }
    write_stdout_line(format_args!(
        "hint: no ClientHello was assembled, so the capture most likely starts after the handshake or does not carry one"
    ))
}

fn session_line(session: &Session) -> String {
    let client = session.client.as_ref();
    let server = session.server.as_ref();
    let mut line = format!(
        "session={} stream=tcp:{} client={} server={} status={} sni={} version={} \
         cipher={} group={} alpn={} selected_alpn={} ja3={} ja4={} frames={}..{} rtt_ms={}",
        session.session,
        session.tcp_stream,
        session.client_endpoint,
        session.server_endpoint,
        session.status,
        optional_display(client.and_then(|client| client.sni.as_deref())),
        optional_display(server.map(version_text).as_deref()),
        optional_display(server.map(cipher_text).as_deref()),
        optional_display(server.and_then(group_text).as_deref()),
        alpn_text(client),
        optional_display(server.and_then(|server| server.alpn.as_deref())),
        optional_display(client.map(|client| client.ja3.as_str())),
        optional_display(client.map(|client| client.ja4.as_str())),
        session.first_frame,
        session.last_frame,
        session
            .handshake_rtt_ms
            .map_or_else(|| "none".to_owned(), |value| format!("{value:.3}")),
    );
    let _ = write!(
        line,
        " scope={} interface={} encapsulation={}",
        session.scope.id,
        optional_display(session.scope.interface),
        encapsulation_text(&session.scope.encapsulation)
    );
    if session.hello_retry {
        line.push_str(" hello_retry=true");
    }
    if !session.alerts.is_empty() {
        line.push_str(" alerts=");
        line.push_str(&comma_separated(session.alerts.iter().map(alert_text)));
    }
    if session.alerts_dropped > 0 {
        let _ = write!(line, " alerts_dropped={}", session.alerts_dropped);
    }
    // Last, because the free-text reason carries spaces.
    if let Some(reason) = &session.reason {
        line.push_str(" reason=");
        line.push_str(reason);
    }
    line
}

fn summary_line(summary: &Summary) -> String {
    let counts = summary.by_status;
    format!(
        "tls sessions={} selected={} omitted={} evicted={} complete={} client_only={} retry={} \
         alert={} malformed={} gap={} truncated={} tcp_streams={} buffer_limit_hits={} \
         udp_443_frames={} frames_matched={} frames_read={}",
        summary.sessions,
        summary.sessions_selected,
        summary.sessions_omitted,
        summary.sessions_evicted,
        counts.complete,
        counts.client_only,
        counts.retry,
        counts.alert,
        counts.malformed,
        counts.gap,
        counts.truncated,
        summary.tcp_streams,
        summary.buffer_limit_hits,
        summary.udp_443_frames,
        summary.frames_matched,
        summary.frames_read,
    )
}

fn version_text(server: &Server) -> String {
    server.selected_version_name.map_or_else(
        || format!("0x{:04x}", server.selected_version),
        |name| name.replace(' ', ""),
    )
}

fn cipher_text(server: &Server) -> String {
    match server.cipher_suite_name {
        Some(name) => format!("0x{:04x}({name})", server.cipher_suite),
        None => format!("0x{:04x}", server.cipher_suite),
    }
}

fn group_text(server: &Server) -> Option<String> {
    let group = server.key_share_group?;
    Some(
        server
            .key_share_group_name
            .map_or_else(|| format!("0x{group:04x}"), ToOwned::to_owned),
    )
}

fn alpn_text(client: Option<&Client>) -> String {
    match client {
        Some(client) if !client.alpn.is_empty() => comma_separated(&client.alpn),
        _ => "none".to_owned(),
    }
}

fn alert_text(alert: &output::tls::Alert) -> String {
    let level = match alert.level {
        ALERT_LEVEL_WARNING => "warning".to_owned(),
        ALERT_LEVEL_FATAL => "fatal".to_owned(),
        level => level.to_string(),
    };
    match alert.description_name {
        Some(name) => format!("{level}:{name}"),
        None => format!("{level}:{}", alert.description),
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use crate::output::tls::Status;

    use super::*;

    fn endpoint(last: u8, port: u16) -> output::analysis::Endpoint {
        output::analysis::Endpoint {
            address: IpAddr::V4(Ipv4Addr::new(192, 0, 2, last)),
            port,
        }
    }

    fn session() -> Session {
        let mut scopes = packetcraftr_core::analysis::scope::Interner::new();
        let id = scopes.intern(None, Vec::new()).unwrap();
        Session {
            scope: scopes.definition(id).unwrap().try_into().unwrap(),
            session: 0,
            tcp_stream: 3,
            client_endpoint: endpoint(1, 40_000),
            server_endpoint: endpoint(2, 443),
            first_frame: 4,
            last_frame: 9,
            handshake_rtt_ms: Some(1.25),
            client: None,
            server: None,
            hello_retry: false,
            alerts: Vec::new(),
            alerts_dropped: 0,
            status: Status::Truncated,
            reason: None,
        }
    }

    #[test]
    fn absent_session_fields_render_as_none_so_the_key_set_never_moves() {
        let line = session_line(&session());
        assert!(line.starts_with(
            "session=0 stream=tcp:3 client=192.0.2.1:40000 server=192.0.2.2:443 \
             status=truncated sni=none version=none cipher=none group=none alpn=none \
             selected_alpn=none ja3=none ja4=none frames=4..9 rtt_ms=1.250"
        ));
    }
}
