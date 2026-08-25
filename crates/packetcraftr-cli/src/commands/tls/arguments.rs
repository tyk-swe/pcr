// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::path::PathBuf;

use clap::{ArgAction, ValueEnum};
use packetcraftr::analysis::tls::{Limits as TlsLimits, Status as AnalysisStatus};

use crate::command_options::OfflineLimitsArgs;

pub(crate) const AFTER_LONG_HELP: &str = r#"Session assembly is computed offline over dissected frames; no live capture or transmission is involved.

Session assembly reads every TCP stream, so a handshake on a non-standard port is found without any configuration. Port bindings belong to the per-frame 'tls' layer: TCP ports 443, 465, 636, 853, 993, 995 and 8443 dissect as TLS by default, and --tls-port adds one more. The flag repeats, adds to the defaults, and 'read' and 'dissect' accept the same flag, so their per-frame view agrees with this one.

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

Text and JSON hold every selected session in memory, bounded by --max-tls-sessions; NDJSON streams each session as it completes and is the format for large captures.

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
    /// Dissect this TCP port as TLS in the per-frame layer, in addition to
    /// the well-known ports; repeatable. Session assembly reads every TCP
    /// stream and needs no port list.
    #[arg(
        long = "tls-port",
        value_name = "PORT",
        action = ArgAction::Append,
        value_parser = clap::value_parser!(u16).range(1..)
    )]
    pub(crate) tls_ports: Vec<u16>,
    /// Maximum handshake bytes buffered across every tracked conversation.
    #[arg(long, default_value_t = TlsLimits::default().max_buffered_bytes)]
    pub(crate) max_tls_buffer_bytes: usize,
    /// Maximum TLS conversations tracked at once, and sessions retained by
    /// text and JSON output.
    #[arg(long, default_value_t = TlsLimits::default().max_sessions)]
    pub(crate) max_tls_sessions: usize,
    #[command(flatten)]
    pub(crate) limits: OfflineLimitsArgs,
}
