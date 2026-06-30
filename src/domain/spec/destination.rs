// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use std::fmt;
use std::net::IpAddr;

use super::error::SpecResult;

use crate::domain::request::DestinationRequest;

use super::utils::parse_ip_address;

#[derive(Debug, Clone, Default)]
pub(crate) struct DestinationSpec {
    pub address: Option<TargetAddress>,
    pub interface: Option<String>,
}

impl DestinationSpec {
    pub(crate) fn from_request(request: &DestinationRequest) -> SpecResult<Self> {
        let mut address = None;
        if let Some(ip) = request.destination_ip.as_ref() {
            address = Some(TargetAddress::Ip(parse_ip_address(ip)?));
        } else if let Some(dest) = request.destination.as_ref() {
            address = Some(
                match (parse_target_address(dest)?, request.resolved_destination) {
                    (TargetAddress::Host(host), Some(ip)) => {
                        TargetAddress::ResolvedHost { host, ip }
                    }
                    (target, _) => target,
                },
            );
        }

        Ok(Self {
            address,
            interface: request.interface.clone(),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum TargetAddress {
    Ip(IpAddr),
    Host(String),
    ResolvedHost { host: String, ip: IpAddr },
}

impl TargetAddress {
    pub(crate) fn resolved_ip(&self) -> Option<IpAddr> {
        match self {
            Self::Ip(ip) | Self::ResolvedHost { ip, .. } => Some(*ip),
            Self::Host(_) => None,
        }
    }
}

impl fmt::Display for TargetAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TargetAddress::Ip(addr) => write!(f, "{addr}"),
            TargetAddress::Host(host) => write!(f, "{host}"),
            TargetAddress::ResolvedHost { ip, .. } => write!(f, "{ip}"),
        }
    }
}

pub(crate) fn parse_target_address(value: &str) -> SpecResult<TargetAddress> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(super::error::SpecError::EmptyTargetAddress);
    }

    if let Ok(addr) = parse_ip_address(trimmed) {
        Ok(TargetAddress::Ip(addr))
    } else {
        Ok(TargetAddress::Host(trimmed.to_string()))
    }
}
