// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::IpAddr;

use packetcraftr::{live as client, live as workflow, packet::Packet};

use super::super::errors::CliError;

pub(crate) fn parse_workflow_target(target: String) -> Result<workflow::target::Target, CliError> {
    target
        .parse::<client::target::Target>()
        .map_err(CliError::classified)
}

pub(crate) fn resolve_live_destination(
    destination: Option<String>,
    packet: &Packet,
    policy: &client::policy::Policy,
) -> Result<Option<IpAddr>, CliError> {
    let Some(destination) = destination else {
        return Ok(None);
    };
    let target = destination
        .parse::<client::target::Target>()
        .map_err(CliError::classified)?;
    let resolved = policy
        .resolve_target(&target, &client::target::SystemResolver)
        .map_err(CliError::classified)?;
    let ip_version = packet
        .iter()
        .find_map(|layer| match layer.protocol_id().as_str() {
            "ipv4" => Some(client::target::Family::Ipv4),
            "ipv6" => Some(client::target::Family::Ipv6),
            _ => None,
        });
    match ip_version {
        Some(version) => resolved
            .address_for_family(version)
            .map(Some)
            .ok_or_else(|| {
                CliError::classified(client::target::Error::AddressFamilyUnavailable {
                    family: version.label(),
                })
            }),
        None => Ok(Some(resolved.selected_address())),
    }
}
