// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::IpAddr;
use std::time::Duration;

use packetcraftr::{client, net, packet, packet::Packet};

use super::super::command_options::RouteArgs;
use super::super::errors::CliError;
use super::super::input::read_recipe;
use super::interface::resolve_interface;
use super::target::resolve_live_destination;

pub(crate) struct PreparedRouteRequest {
    pub(crate) packet: Packet,
    pub(crate) destination: Option<IpAddr>,
    pub(crate) options: net::route::Options,
    pub(crate) policy: client::policy::Policy,
}

pub(crate) fn workflow_exchange_options(
    send: client::send::Options,
    timeout: Duration,
    max_template_packets: usize,
    limits: net::capture::Limits,
) -> Result<client::exchange::Options, CliError> {
    let mut options = client::exchange::Options {
        send,
        timeout,
        max_template_packets,
        max_unsolicited: limits.max_frames,
        max_responses: limits.max_frames,
        max_capture_queue_frames: limits.max_frames,
        max_captured_bytes: limits.max_bytes,
        capture_overflow_policy: limits.overflow_policy,
        decode: packet::decode::Options::default(),
    };
    options.decode.max_packet_size = limits.snap_length;
    options.validate().map_err(CliError::classified)?;
    Ok(options)
}

pub(crate) fn prepare_route_request(
    arguments: RouteArgs,
    policy: client::policy::Policy,
    registry: &packet::registry::Registry,
) -> Result<PreparedRouteRequest, CliError> {
    let RouteArgs {
        recipe,
        destination,
        interface,
        source,
        link_mode,
    } = arguments;
    let packet = read_recipe(recipe, registry)?;
    policy.validate().map_err(CliError::classified)?;
    // This check intentionally precedes interface discovery and route lookup.
    policy
        .authorize_packet_destinations(&packet)
        .map_err(CliError::classified)?;
    let destination = resolve_live_destination(destination, &packet, &policy)?;
    let interface = resolve_interface(interface, &net::interface::SystemProvider)?;
    Ok(PreparedRouteRequest {
        packet,
        destination,
        options: net::route::Options {
            link_mode: link_mode.into(),
            interface,
            preferred_source: source,
        },
        policy,
    })
}
