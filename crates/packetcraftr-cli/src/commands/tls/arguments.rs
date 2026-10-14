// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::path::PathBuf;

use clap::{ArgAction, ValueEnum};
use packetcraftr_core::analysis::tls::Limits as TlsLimits;
use packetcraftr_core::analysis::tls::MAX_DIRECTION_BUFFER;
use packetcraftr_core::analysis::tls::Status as AnalysisStatus;

use crate::command_options::{DecodeArgs, OfflineLimitsArgs};

// The `--max-tls-buffer-bytes` help text below spells out the floor.
const _: () = assert!(MAX_DIRECTION_BUFFER == 135_168);

pub(crate) const AFTER_LONG_HELP: &str = r#"Offline TLS handshake assembly across all TCP streams (independent of --tls-port,
which only configures per-frame `tls` layer bindings). Selectors (--stream,
--sni, --server-port, --status) filter assembled sessions rather than raw frames;
JSON is bounded by --max-output-sessions while text and NDJSON stream all
selected sessions.

Statuses: complete, client_only, retry, alert, malformed, gap, truncated.

Examples:
  packetcraftr analyze tls examples/captures/tls-handshake.pcapng
  packetcraftr analyze tls capture.pcapng --sni '*.example.test' --status complete
  packetcraftr analyze tls capture.pcapng --stream tcp:12
  packetcraftr analyze tls capture.pcapng --server-port 4433 --status complete --status alert
  packetcraftr --output ndjson analyze tls capture.pcapng | jq -r 'select(.event == "session") | .result.client.ja4'"#;

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
    /// Classic PCAP or PCAPNG input path; - reads redirected stdin.
    pub(crate) path: PathBuf,
    /// Assemble only one conversation, as `tcp:INDEX`, using the same indices
    /// stats reports and stream filters match.
    #[arg(long, value_name = "TRANSPORT:INDEX", value_parser = crate::command_options::stream_selector)]
    pub(crate) stream:
        Option<crate::command_options::Selector<packetcraftr_core::analysis::StreamRef>>,
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
    pub(crate) decode: DecodeArgs,
    /// Maximum handshake bytes buffered across every tracked conversation.
    /// The smallest accepted value is 135168, which one direction of one
    /// conversation may buffer on its own.
    #[arg(long, default_value_t = TlsLimits::default().max_buffered_bytes)]
    pub(crate) max_tls_buffer_bytes: usize,
    /// Maximum TLS conversations tracked concurrently (including closed state).
    #[arg(long, default_value_t = TlsLimits::default().max_sessions)]
    pub(crate) max_tls_sessions: usize,
    /// Maximum selected sessions retained by aggregate JSON; zero retains none.
    /// Does not change analysis state. Text and NDJSON emit all selected sessions.
    #[arg(long, default_value_t = TlsLimits::default().max_sessions)]
    pub(crate) max_output_sessions: usize,
    #[command(flatten)]
    pub(crate) limits: OfflineLimitsArgs,
}
