// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! The route pieces live preparation assembles: the requested route options,
//! the authorized expansion, and the resolved destination.

use std::net::IpAddr;

use crate::command_options::RouteSelectionArgs;
use crate::errors::CliError;
use packetcraftr_core as core;
use packetcraftr_core::packet::Packet;
use packetcraftr_core::protocol::BuiltinProtocol;

/// The requested route: link mode, source preference, and the interface
/// selector the client resolves after it admits each operation. A malformed
/// `--interface` fails here, before any provider is consulted.
pub(super) fn options(
    route: &RouteSelectionArgs,
) -> Result<packetcraftr::route::Options, CliError> {
    let interface = route
        .interface
        .as_ref()
        .map(crate::command_options::Selector::get)
        .transpose()?
        .map(Into::into);
    Ok(packetcraftr::route::Options {
        link_mode: route.link_mode.into(),
        interface,
        preferred_source: route.source,
    })
}

/// Expands the bounded template lazily and authorizes every expanded packet's
/// declared destinations before hostname work, returning the first packet.
/// The library repeats these checks against every final packet before
/// transmission.
pub(super) fn authorize_expanded_destinations(
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

/// Resolves an explicit `destination` under `policy` for a packet whose
/// declared destinations the caller has already authorized, choosing the
/// address family the packet's IP layer requires.
pub(super) fn destination(
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
        .find_map(|layer| match BuiltinProtocol::of(layer) {
            Some(BuiltinProtocol::Ipv4) => Some(packetcraftr::target::Family::Ipv4),
            Some(BuiltinProtocol::Ipv6) => Some(packetcraftr::target::Family::Ipv6),
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
