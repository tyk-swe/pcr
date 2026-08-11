// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::IpAddr;

use packetcraftr::core::Packet;

use super::super::errors::CliError;

pub(crate) fn parse_workflow_target(
    target: String,
) -> Result<packetcraftr::target::Target, CliError> {
    target
        .parse::<packetcraftr::target::Target>()
        .map_err(CliError::classified)
}

pub(crate) fn resolve_live_destination(
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
