// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::IpAddr;

use packetcraftr::{core, core::Packet, netio as net};

use super::super::command_options::RouteArgs;
use super::super::errors::CliError;
use super::super::input::read_recipe;
use super::interface;

pub(crate) struct Prepared {
    pub(crate) packet: Packet,
    pub(crate) destination: Option<IpAddr>,
    pub(crate) options: net::route::Options,
    pub(crate) policy: packetcraftr::policy::Policy,
    pub(crate) diagnostics: Vec<core::diagnostic::Diagnostic>,
}

pub(crate) fn prepare_route(
    arguments: RouteArgs,
    policy: packetcraftr::policy::Policy,
    registry: &core::registry::Registry,
) -> Result<Prepared, CliError> {
    let RouteArgs {
        recipe,
        destination,
        route,
    } = arguments;
    let (packet, diagnostics) = read_recipe(recipe, registry)?;
    policy.validate().map_err(CliError::classified)?;
    // This check intentionally precedes interface discovery and route lookup.
    policy
        .authorize_packet_destinations(&packet)
        .map_err(CliError::classified)?;
    let destination = resolve_destination(destination, &packet, &policy)?;
    let interface = interface::resolve(route.interface, &net::interface::SystemProvider)?;
    Ok(Prepared {
        packet,
        destination,
        options: net::route::Options {
            link_mode: route.link_mode.into(),
            interface,
            preferred_source: route.source,
        },
        policy,
        diagnostics,
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
