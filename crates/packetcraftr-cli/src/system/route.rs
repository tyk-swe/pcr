// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::IpAddr;

use packetcraftr_core as core;
use packetcraftr_core::packet::Packet;
use packetcraftr_netio as net;

use super::interface;
use crate::command_options::{RouteArgs, RouteSelectionArgs};
use crate::errors::CliError;
use crate::input::read_recipe;

/// One packet with the destination, route options, and policy the CLI
/// resolved for it, ready for a live send, exchange, or plan.
pub(crate) struct RoutedPacket {
    pub(crate) packet: Packet,
    pub(crate) destination: Option<IpAddr>,
    pub(crate) options: net::route::Options,
    pub(crate) policy: packetcraftr::policy::Policy,
}

/// Reads one recipe, validates `policy`, and authorizes the packet's declared
/// destinations before hostname or interface work.
pub(crate) fn prepare_route(
    arguments: RouteArgs,
    policy: packetcraftr::policy::Policy,
    registry: &core::registry::Registry,
) -> Result<RoutedPacket, CliError> {
    let RouteArgs {
        recipe,
        destination,
        route,
    } = arguments;
    let packet = read_recipe(recipe, registry, core::layout::DEFAULT_MAX_LAYERS)?;
    policy.validate().map_err(CliError::classified)?;
    // This check intentionally precedes interface discovery and route lookup.
    policy
        .authorize_packet_destinations(&packet)
        .map_err(CliError::classified)?;
    resolve_route(packet, destination, route, policy)
}

/// Expands the bounded template lazily and authorizes every expanded packet's
/// declared destinations before hostname or interface work, then prepares the
/// route for the first packet. The caller has already validated `policy`; the
/// library repeats these checks against every final packet before
/// transmission.
pub(crate) fn prepare_expanded_route(
    template: &core::template::Template,
    max_template_packets: usize,
    destination: Option<String>,
    route: RouteSelectionArgs,
    policy: packetcraftr::policy::Policy,
) -> Result<RoutedPacket, CliError> {
    let first = authorize_expanded_destinations(template, max_template_packets, &policy)?;
    resolve_route(first, destination, route, policy)
}

fn authorize_expanded_destinations(
    template: &core::template::Template,
    max_template_packets: usize,
    policy: &packetcraftr::policy::Policy,
) -> Result<Packet, CliError> {
    let mut packets = template
        .expand(max_template_packets)
        .map_err(CliError::classified)?;
    let first = packets
        .next()
        .transpose()
        .map_err(CliError::classified)?
        .ok_or_else(|| {
            CliError::new(
                core::error::Kind::Usage,
                "packet set must contain at least one packet",
            )
        })?;
    policy
        .authorize_packet_destinations(&first)
        .map_err(CliError::classified)?;
    for packet in packets {
        crate::cancellation::check()?;
        policy
            .authorize_packet_destinations(&packet.map_err(CliError::classified)?)
            .map_err(CliError::classified)?;
    }
    Ok(first)
}

/// Resolves the destination and interface for a packet whose declared
/// destinations the caller has already authorized.
fn resolve_route(
    packet: Packet,
    destination: Option<String>,
    route: RouteSelectionArgs,
    policy: packetcraftr::policy::Policy,
) -> Result<RoutedPacket, CliError> {
    let destination = resolve_destination(destination, &packet, &policy)?;
    let interface = interface::InterfaceSelector::parse_optional(route.interface.as_deref())?
        .map(|selector| interface::resolve(selector, &net::interface::SystemProvider))
        .transpose()?;
    Ok(RoutedPacket {
        packet,
        destination,
        options: net::route::Options {
            link_mode: route.link_mode.into(),
            interface,
            preferred_source: route.source,
        },
        policy,
    })
}

fn resolve_destination(
    destination: Option<String>,
    packet: &Packet,
    policy: &packetcraftr::policy::Policy,
) -> Result<Option<IpAddr>, CliError> {
    let Some(destination) = destination else {
        return Ok(None);
    };
    let target = destination
        .parse::<packetcraftr::target::Target>()
        .map_err(CliError::classified)?;
    let resolved = policy
        .resolve_target(&target, &packetcraftr::target::SystemResolver)
        .map_err(CliError::classified)?;
    let ip_version = packet
        .iter()
        .find_map(|layer| match layer.protocol_id().as_str() {
            "ipv4" => Some(packetcraftr::target::Family::Ipv4),
            "ipv6" => Some(packetcraftr::target::Family::Ipv6),
            _ => None,
        });
    match ip_version {
        Some(version) => resolved
            .address_for_family(version)
            .map(Some)
            .ok_or_else(|| {
                CliError::classified(packetcraftr::target::Error::AddressFamilyUnavailable {
                    family: version.label(),
                })
            }),
        None => Ok(Some(resolved.selected_address())),
    }
}
