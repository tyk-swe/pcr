// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::path::PathBuf;

use clap::{ArgAction, ValueEnum};
use packetcraftr::analysis::tls::{Limits as TlsLimits, Status as AnalysisStatus};

use crate::command_options::{OfflineLimitsArgs, TlsPortArgs};

pub(crate) const AFTER_LONG_HELP: &str = r#"Session assembly is computed offline over dissected frames; no live capture or transmission is involved.

Session assembly reads every TCP stream, so a handshake on a non-standard port is assembled with no flag at all. --tls-port does not change what this command assembles. It changes the per-frame 'tls' layer, which binds TCP ports 443, 465, 636, 853, 993, 995 and 8443 by default, and it changes the port list printed when no session was assembled. The flag repeats, adds to the defaults, and 'read' and 'dissect' take the same flag, so their per-frame view agrees with this one.

Statuses:
  complete     a ClientHello and its matching ServerHello were both assembled
  client_only  the connection ended before any ServerHello
  retry        a HelloRetryRequest arrived and the real ServerHello never did
  alert        a fatal alert in the clear ended the handshake
  malformed    handshake bytes could not be parsed, or a buffer ceiling was hit
  gap          handshake bytes were missing, or the capture started mid-handshake
  truncated    the capture ended while the handshake was still in flight

Selectors run on assembled sessions, not on frames, so there is deliberately no --filter: a frame filter such as 'tls.sni == "x"' would drop the ServerHello frames and turn every session into client_only. --stream is the one exception, applied as 'tcp.stream == N', which is stream-preserving. --sni matches case-insensitively and takes '*' as a leading or trailing wildcard; --status repeats and matches any of the listed statuses.

The per-frame 'tls' layer is a different view: read --filter 'tls.sni contains "x"' sees only the hellos that fit in a single segment, and 'tls.incomplete' filters the frames whose record continues into the next one. Use this command for the assembled answer.

Text prints each selected session as it is assembled and leaves none out. JSON holds every selected session in memory to emit one document, bounded by --max-tls-sessions, and reports what that bound left out as sessions_omitted. NDJSON streams each session as it completes and is the format for large captures.

Examples:
  packetcraftr tls examples/captures/tls-handshake.pcapng
  packetcraftr tls capture.pcapng --sni '*.example.test' --status complete
  packetcraftr tls capture.pcapng --stream tcp:12
  packetcraftr tls capture.pcapng --server-port 4433 --status complete --status alert
  packetcraftr --output ndjson tls capture.pcapng | jq -r 'select(.result.event == "session") | .result.client.ja4'"#;

/// Session status selector for `tls`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
#[value(rename_all = "snake_case")]
pub(crate) enum Status {
    /// A ClientHello and its matching ServerHello were both assembled.
    Complete,
    /// The connection ended before any ServerHello.
    ClientOnly,
    /// A HelloRetryRequest arrived and the real ServerHello never did.
    Retry,
    /// A fatal alert in the clear ended the handshake.
    Alert,
    /// Handshake bytes could not be parsed, or a buffer ceiling was hit.
    Malformed,
    /// Handshake bytes were missing, or the capture started mid-handshake.
    Gap,
    /// The capture ended while the handshake was still in flight.
    Truncated,
}

impl From<Status> for AnalysisStatus {
    fn from(value: Status) -> Self {
        match value {
            Status::Complete => Self::Complete,
            Status::ClientOnly => Self::ClientOnly,
            Status::Retry => Self::Retry,
            Status::Alert => Self::Alert,
            Status::Malformed => Self::Malformed,
            Status::Gap => Self::Gap,
            Status::Truncated => Self::Truncated,
        }
    }
}

#[derive(Debug, clap::Args)]
pub(crate) struct Args {
    /// Classic PCAP or PCAPNG input path.
    pub(crate) path: PathBuf,
    /// Assemble only one conversation, as `tcp:INDEX`, using the same indices
    /// stats reports and stream filters match.
    #[arg(long, value_name = "TRANSPORT:INDEX")]
    pub(crate) stream: Option<String>,
    /// Keep sessions whose server name matches, case-insensitively; `*` is
    /// accepted as a leading or trailing wildcard.
    #[arg(long, value_name = "PATTERN")]
    pub(crate) sni: Option<String>,
    /// Keep sessions whose server endpoint used this port.
    #[arg(long, value_name = "PORT")]
    pub(crate) server_port: Option<u16>,
    /// Keep sessions with this status; repeatable, matching any listed status.
    #[arg(long = "status", value_enum, value_name = "STATUS", action = ArgAction::Append)]
    pub(crate) statuses: Vec<Status>,
    #[command(flatten)]
    pub(crate) tls_ports: TlsPortArgs,
    /// Maximum handshake bytes buffered across every tracked conversation.
    /// The smallest accepted value is 135168, which one direction of one
    /// conversation may buffer on its own.
    #[arg(long, default_value_t = TlsLimits::default().max_buffered_bytes)]
    pub(crate) max_tls_buffer_bytes: usize,
    /// Maximum TLS conversations tracked at once, and sessions retained by
    /// the JSON document. Text and NDJSON report every selected session.
    #[arg(long, default_value_t = TlsLimits::default().max_sessions)]
    pub(crate) max_tls_sessions: usize,
    #[command(flatten)]
    pub(crate) limits: OfflineLimitsArgs,
}

#[cfg(test)]
mod tests {
    use packetcraftr::core::protocol::builtin::TLS_TCP_PORTS;

    use super::*;

    /// The ports the long help names, in the order it names them.
    fn documented_ports() -> Vec<u16> {
        let (_, rest) = AFTER_LONG_HELP
            .split_once("binds TCP ports ")
            .expect("the long help introduces the default port list");
        let (list, _) = rest
            .split_once(" by default")
            .expect("the long help closes the default port list");
        list.split(|character: char| !character.is_ascii_digit())
            .filter(|piece| !piece.is_empty())
            .map(|piece| piece.parse().expect("a documented port is numeric"))
            .collect()
    }

    #[test]
    fn the_long_help_names_exactly_the_ports_the_registry_binds() {
        assert_eq!(documented_ports(), TLS_TCP_PORTS);
    }

    #[test]
    fn the_status_selector_names_match_the_analysis_statuses() {
        let selectors = Status::value_variants()
            .iter()
            .map(|status| {
                status
                    .to_possible_value()
                    .expect("every status selector is selectable")
                    .get_name()
                    .to_owned()
            })
            .collect::<Vec<_>>();
        let statuses = AnalysisStatus::ALL
            .into_iter()
            .map(AnalysisStatus::as_str)
            .collect::<Vec<_>>();
        assert_eq!(selectors, statuses);
    }
}
