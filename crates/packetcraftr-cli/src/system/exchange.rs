// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::time::Duration;

use packetcraftr_core as core;
use packetcraftr_netio as net;

use crate::errors::CliError;

pub(crate) fn collection(
    timeout: Duration,
    max_template_packets: usize,
    limits: net::capture::Limits,
) -> Result<packetcraftr::exchange::Collection, CliError> {
    let mut collection = packetcraftr::exchange::Collection {
        max_unmatched_frames: limits.max_frames,
        max_responses: limits.max_frames,
        capture: limits,
        ..packetcraftr::exchange::Collection::default()
    };
    collection.decode.limits.max_packet_size = limits.snap_length;
    packetcraftr::exchange::Request {
        timeout,
        max_template_packets,
        collection: collection.clone(),
        ..packetcraftr::exchange::Request::new(
            core::template::Template::new(core::packet::Packet::new()),
            packetcraftr::send::Options::default(),
        )
    }
    .validate()
    .map_err(CliError::classified)?;
    Ok(collection)
}
