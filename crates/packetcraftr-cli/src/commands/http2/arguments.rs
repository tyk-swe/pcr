// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::path::PathBuf;

use packetcraftr_core::analysis::{StreamRef, http2::Limits};

use crate::command_options::{
    ApplicationLimitsArgs, DecodeArgs, OfflineLimitsArgs, Selector, stream_selector,
};

pub(crate) const AFTER_LONG_HELP: &str = r"Cleartext HTTP/2 connections are inspected offline over reassembled TCP streams on ports 80 and 8080 and every --http2-port, including prior-knowledge and h2c upgrade startups; TLS is not decrypted, so encrypted connections report unsupported. Decoded DATA bodies are counted and discarded; undecodable or truncated wire can be retained as bounded failure evidence.

--stream keeps one TCP conversation, as tcp:INDEX. Text prints per-frame and per-message summaries with all captured strings escaped; JSON and NDJSON keep exact bytes as hex.

Examples:
  packetcraftr http2 capture.pcapng
  packetcraftr http2 capture.pcapng --http2-port 8000 --stream tcp:1
  packetcraftr --output ndjson http2 capture.pcapng";

#[derive(Debug, clap::Args)]
pub(crate) struct Args {
    #[arg(help = "PCAP/PCAPNG input; - reads redirected stdin. gzip and Zstd are detected.")]
    pub(crate) path: PathBuf,
    #[arg(
        long,
        value_name = "TRANSPORT:INDEX",
        value_parser = stream_selector,
        help = "Select a whole TCP conversation, using tcp:INDEX."
    )]
    pub(crate) stream: Option<Selector<StreamRef>>,
    #[arg(
        long = "http2-port",
        value_name = "PORT",
        value_parser = clap::value_parser!(u16).range(1..),
        help = "Additional ports to inspect; repeat to add services. Ports 80 and 8080 are always inspected. Add 443 explicitly to classify encrypted HTTPS traffic as unsupported; TLS is not decrypted."
    )]
    pub(crate) http2_ports: Vec<u16>,
    #[arg(
        long,
        default_value_t = Limits::default().max_frames,
        help = "Maximum HTTP/2 frames analyzed across the capture."
    )]
    pub(crate) max_http2_frames: u64,
    #[arg(
        long,
        default_value_t = Limits::default().max_streams,
        help = "Maximum admitted HTTP/2 streams across all selected TCP conversations."
    )]
    pub(crate) max_http2_streams: usize,
    #[arg(
        long,
        default_value_t = Limits::default().max_active_streams,
        help = "Maximum live HTTP/2 streams per connection, including reserved ones."
    )]
    pub(crate) max_http2_active_streams: usize,
    #[arg(
        long,
        default_value_t = Limits::default().max_frame_bytes,
        help = "Maximum HTTP/2 frame payload bytes."
    )]
    pub(crate) max_http2_frame_bytes: usize,
    #[arg(
        long,
        default_value_t = Limits::default().max_header_block_bytes,
        help = "Maximum bytes in one header block, including continuations."
    )]
    pub(crate) max_http2_header_block_bytes: usize,
    #[arg(
        long,
        default_value_t = Limits::default().max_header_bytes,
        help = "Maximum decoded header-list bytes per block."
    )]
    pub(crate) max_http2_header_bytes: usize,
    #[arg(
        long,
        default_value_t = Limits::default().max_headers,
        help = "Maximum header fields per block."
    )]
    pub(crate) max_http2_headers: usize,
    #[arg(
        long,
        default_value_t = Limits::default().max_table_bytes,
        help = "Maximum HPACK dynamic-table bytes per direction."
    )]
    pub(crate) max_http2_table_bytes: usize,
    #[arg(
        long,
        default_value_t = Limits::default().max_continuations,
        help = "Maximum CONTINUATION frames per header block."
    )]
    pub(crate) max_http2_continuations: usize,
    #[arg(
        long,
        default_value_t = Limits::default().max_pending_settings,
        help = "Maximum unacknowledged SETTINGS per direction."
    )]
    pub(crate) max_http2_pending_settings: usize,
    #[arg(
        long,
        default_value_t = Limits::default().max_body_bytes,
        help = "Maximum counted entity bytes in one message. Bodies are discarded."
    )]
    pub(crate) max_http2_body_bytes: u64,
    #[command(flatten)]
    pub(crate) application: ApplicationLimitsArgs,
    #[command(flatten)]
    pub(crate) decode: DecodeArgs,
    #[command(flatten)]
    pub(crate) limits: OfflineLimitsArgs,
}

impl Args {
    pub(crate) fn http2_limits(&self) -> Limits {
        Limits {
            max_frames: self.max_http2_frames,
            max_streams: self.max_http2_streams,
            max_active_streams: self.max_http2_active_streams,
            max_frame_bytes: self.max_http2_frame_bytes,
            max_header_block_bytes: self.max_http2_header_block_bytes,
            max_header_bytes: self.max_http2_header_bytes,
            max_headers: self.max_http2_headers,
            max_table_bytes: self.max_http2_table_bytes,
            max_continuations: self.max_http2_continuations,
            max_pending_settings: self.max_http2_pending_settings,
            max_body_bytes: self.max_http2_body_bytes,
        }
    }
}
