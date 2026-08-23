// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::time::Duration;

use packetcraftr::netio as net;

use super::arguments::Args;
use crate::input::parse_target;
use packetcraftr::BoundaryError;

pub(super) fn prepare_request(
    arguments: &Args,
    queue_limits: net::capture::Limits,
) -> Result<packetcraftr::traceroute::Request, BoundaryError> {
    let strategy: packetcraftr::traceroute::Strategy = arguments.strategy.into();
    let destination_port = match strategy {
        packetcraftr::traceroute::Strategy::Udp => Some(
            arguments
                .port
                .unwrap_or(packetcraftr::traceroute::DEFAULT_TRACEROUTE_UDP_PORT),
        ),
        packetcraftr::traceroute::Strategy::Tcp => Some(
            arguments
                .port
                .unwrap_or(packetcraftr::traceroute::DEFAULT_TRACEROUTE_TCP_PORT),
        ),
        packetcraftr::traceroute::Strategy::Icmp => arguments.port,
    };
    let trace_limits = packetcraftr::traceroute::Limits {
        max_probes: arguments.max_probes,
        max_duration: Duration::from_millis(arguments.max_duration_ms),
        max_evidence_frames: queue_limits.max_frames,
        max_evidence_bytes: queue_limits.max_bytes,
        max_undecoded: arguments.max_undecoded,
    };
    let request = packetcraftr::traceroute::Request {
        target: parse_target(arguments.target.clone())?,
        strategy,
        address_family: arguments.family.into(),
        destination_port,
        first_hop: arguments.first_hop,
        max_hops: arguments.max_hops,
        probes_per_hop: arguments.attempts,
        timeout: Duration::from_millis(arguments.timeout_ms),
        probes_per_second: arguments.rate,
        limits: trace_limits,
    };
    request.validate().map_err(BoundaryError::from_error)?;
    Ok(request)
}
