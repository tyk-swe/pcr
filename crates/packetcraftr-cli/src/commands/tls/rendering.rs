// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use packetcraftr::{analysis, core, output};

use crate::commands::format::ToolFormat;
use crate::commands::offline_analysis::Retained;
use crate::errors::CliError;
use crate::rendering::{StreamEncoder, comma_separated, emit_aggregate, write_stdout_line};

use analysis::tls::{ALERT_LEVEL_FATAL, ALERT_LEVEL_WARNING};
use output::tls::{Client, Server, Session, Summary};

/// What has been reported so far.
///
/// The retention ceiling is a property of the JSON document, which has to hold
/// every session in memory before it can be written: past `--max-tls-sessions`
/// the document keeps the sessions it already has and says in the summary how
/// many it left out. Text and NDJSON write each session as it completes, so
/// neither holds anything and neither ever leaves a session out.
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

    pub(super) const fn counts(&self) -> output::tls::SelectionCounts {
        output::tls::SelectionCounts {
            selected: self.selected,
            omitted: self.retained.omitted(),
        }
    }

    /// Counts a session the selectors kept, whatever the format does with it.
    fn select(&mut self) {
        self.selected = self.selected.saturating_add(1);
    }
}

pub(super) fn render_session(
    format: ToolFormat,
    session: analysis::tls::Session,
    state: &mut State,
    stream: &StreamEncoder,
) -> Result<(), CliError> {
    let session = Session::from(session);
    state.select();
    match format {
        ToolFormat::Text => write_stdout_line(format_args!("{}", session_line(&session))),
        ToolFormat::Json => {
            state.retained.push(session);
            Ok(())
        }
        ToolFormat::Ndjson => {
            Ok(stream.emit_data(output::tls::Event::session(session), Vec::new())?)
        }
    }
}

pub(super) fn render_text(
    state: &State,
    summary: &Summary,
    extra_ports: &[u16],
) -> Result<(), CliError> {
    if state.selected == 0 {
        match unmatched_note(summary) {
            Some(note) => write_stdout_line(format_args!("{note}"))?,
            None => render_empty(summary, extra_ports)?,
        }
    }
    write_stdout_line(format_args!("{}", summary_line(summary)))
}

pub(super) fn render_aggregate(state: State, summary: Summary) -> Result<(), CliError> {
    emit_aggregate(
        output::contract::Command::Tls,
        output::tls::Report {
            sessions: state.retained.into_items(),
            summary,
        },
        Vec::new(),
    )
}

pub(super) fn render_stream(summary: Summary, stream: &StreamEncoder) -> Result<(), CliError> {
    Ok(stream.complete(output::tls::Event::complete(summary), Vec::new())?)
}

/// The single line for selectors that kept none of the sessions that were
/// assembled.
///
/// `None` when nothing was assembled at all: that is a different answer, and
/// [`render_empty`] gives it. Telling someone whose `--sni` simply matched
/// nothing that no session was assembled would send them looking for a
/// capture problem that is not there.
fn unmatched_note(summary: &Summary) -> Option<String> {
    (summary.sessions > 0).then(|| {
        format!(
            "no session matched the selectors ({} assembled)",
            summary.sessions
        )
    })
}

/// Says what was read and where to look next, so an empty report is never
/// mistaken for "this capture has no TLS".
fn render_empty(summary: &Summary, extra_ports: &[u16]) -> Result<(), CliError> {
    write_stdout_line(format_args!(
        "no TLS sessions assembled: {} frame(s) read, {} matched, {} TCP conversation(s)",
        summary.frames_read, summary.frames_matched, summary.tcp_streams,
    ))?;
    let mut ports = core::protocol::builtin::TLS_TCP_PORTS.to_vec();
    ports.extend_from_slice(extra_ports);
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

/// One session, one line, so the output survives grep, sort, and cut.
fn session_line(session: &Session) -> String {
    let client = session.client.as_ref();
    let server = session.server.as_ref();
    let mut line = format!(
        "session={} stream=tcp:{} client={}:{} server={}:{} status={} sni={} version={} \
         cipher={} group={} alpn={} selected_alpn={} ja3={} ja4={} frames={}..{} rtt_ms={}",
        session.session,
        session.tcp_stream,
        session.client_endpoint.address,
        session.client_endpoint.port,
        session.server_endpoint.address,
        session.server_endpoint.port,
        session.status,
        optional(client.and_then(|client| client.sni.as_deref())),
        optional(server.map(version_text).as_deref()),
        optional(server.map(cipher_text).as_deref()),
        optional(server.and_then(group_text).as_deref()),
        alpn_text(client),
        optional(server.and_then(|server| server.alpn.as_deref())),
        optional(client.map(|client| client.ja3.as_str())),
        optional(client.map(|client| client.ja4.as_str())),
        session.first_frame,
        session.last_frame,
        session
            .handshake_rtt_ms
            .map_or_else(|| "none".to_owned(), |value| format!("{value:.3}")),
    );
    if session.hello_retry {
        line.push_str(" hello_retry=true");
    }
    if !session.alerts.is_empty() {
        line.push_str(" alerts=");
        line.push_str(&comma_separated(
            session.alerts.iter().map(alert_text).collect::<Vec<_>>(),
        ));
    }
    if session.alerts_dropped > 0 {
        line.push_str(&format!(" alerts_dropped={}", session.alerts_dropped));
    }
    // Last, because it is the one field that carries spaces.
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

fn optional(value: Option<&str>) -> &str {
    value.unwrap_or("none")
}

/// `TLS1.3`, with the registry's space removed so one field stays one token.
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

    use output::tls::Status;

    use super::*;

    fn endpoint(last: u8, port: u16) -> output::tls::Endpoint {
        output::tls::Endpoint {
            address: IpAddr::V4(Ipv4Addr::new(192, 0, 2, last)),
            port,
        }
    }

    fn session() -> Session {
        Session {
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

    #[test]
    fn known_code_points_render_with_their_registered_names() {
        let mut session = session();
        session.status = Status::Complete;
        session.server = Some(Server {
            selected_version: 0x0304,
            selected_version_name: Some("TLS 1.3"),
            cipher_suite: 0x1301,
            cipher_suite_name: Some("TLS_AES_128_GCM_SHA256"),
            alpn: None,
            key_share_group: Some(0x001d),
            key_share_group_name: Some("x25519"),
            ja3s: "s".to_owned(),
            ja3s_raw: "raw".to_owned(),
        });
        let line = session_line(&session);
        assert!(line.contains(" version=TLS1.3 "), "{line}");
        assert!(
            line.contains(" cipher=0x1301(TLS_AES_128_GCM_SHA256) group=x25519 "),
            "{line}"
        );
    }

    #[test]
    fn unregistered_code_points_render_as_hex() {
        let mut session = session();
        session.server = Some(Server {
            selected_version: 0x0f0f,
            selected_version_name: None,
            cipher_suite: 0x0f0f,
            cipher_suite_name: None,
            alpn: Some("http/1.1".to_owned()),
            key_share_group: Some(0x0f0f),
            key_share_group_name: None,
            ja3s: "s".to_owned(),
            ja3s_raw: "raw".to_owned(),
        });
        let line = session_line(&session);
        assert!(
            line.contains(" version=0x0f0f cipher=0x0f0f group=0x0f0f "),
            "{line}"
        );
        assert!(line.contains(" selected_alpn=http/1.1 "), "{line}");
    }

    #[test]
    fn diagnostic_fields_trail_the_stable_key_set() {
        let mut session = session();
        session.hello_retry = true;
        session.alerts = vec![
            output::tls::Alert {
                level: 2,
                description: 40,
                description_name: Some("handshake_failure"),
            },
            output::tls::Alert {
                level: 1,
                description: 200,
                description_name: None,
            },
            output::tls::Alert {
                level: 7,
                description: 40,
                description_name: Some("handshake_failure"),
            },
        ];
        session.alerts_dropped = 4;
        session.reason = Some("the capture ended while the handshake was in flight".to_owned());
        let line = session_line(&session);
        assert!(
            line.contains(
                " hello_retry=true alerts=fatal:handshake_failure,warning:200,7:handshake_failure \
                 alerts_dropped=4 reason=the capture ended"
            ),
            "{line}"
        );
    }

    #[test]
    fn the_retention_ceiling_applies_to_the_aggregate_document_alone() {
        let mut state = State::new(2);
        for _ in 0..5 {
            state.select();
            state.retained.push(session());
        }
        assert_eq!(state.counts().selected, 5);
        assert_eq!(state.counts().omitted, 3);
        assert_eq!(state.retained.into_items().len(), 2);

        // Text counts every session it printed and leaves none out.
        let mut streaming = State::new(2);
        for _ in 0..5 {
            streaming.select();
        }
        assert_eq!(streaming.counts().selected, 5);
        assert_eq!(streaming.counts().omitted, 0);
    }

    #[test]
    fn selectors_that_match_nothing_read_differently_from_a_capture_without_tls() {
        let summary = |sessions: u64| Summary {
            sessions,
            ..Summary::default()
        };
        assert_eq!(
            unmatched_note(&summary(3)).as_deref(),
            Some("no session matched the selectors (3 assembled)")
        );
        assert_eq!(unmatched_note(&summary(0)), None);
    }
}
