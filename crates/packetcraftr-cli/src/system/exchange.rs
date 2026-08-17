// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::time::Duration;

use packetcraftr::{core, netio as net};

use super::super::errors::CliError;

pub(crate) fn options(
    send: packetcraftr::send::Options,
    timeout: Duration,
    max_template_packets: usize,
    limits: net::capture::Limits,
) -> Result<packetcraftr::exchange::Options, CliError> {
    let mut options = packetcraftr::exchange::Options {
        send,
        timeout,
        max_template_packets,
        max_unmatched_frames: limits.max_frames,
        max_responses: limits.max_frames,
        max_capture_queue_frames: limits.max_frames,
        max_captured_bytes: limits.max_bytes,
        capture_overflow_policy: limits.overflow_policy,
        decode: core::decode::Options::default(),
    };
    options.decode.max_packet_size = limits.snap_length;
    options.validate().map_err(CliError::classified)?;
    Ok(options)
}
