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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::request::DestinationRequest;
    use std::net::{IpAddr, Ipv4Addr};

    #[test]
    fn parse_target_address_returns_ip_for_ip_literal() {
        let target = parse_target_address(" 192.0.2.10 ").unwrap();

        assert_eq!(
            target,
            TargetAddress::Ip(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)))
        );
    }

    #[test]
    fn parse_target_address_returns_host_for_non_ip() {
        let target = parse_target_address(" example.test ").unwrap();

        assert_eq!(target, TargetAddress::Host("example.test".to_string()));
    }

    #[test]
    fn parse_target_address_rejects_empty_input() {
        let err = parse_target_address(" \t ").unwrap_err();

        assert!(matches!(
            err,
            super::super::error::SpecError::EmptyTargetAddress
        ));
    }

    #[test]
    fn destination_spec_prefers_destination_ip_over_destination() {
        let spec = DestinationSpec::from_request(&DestinationRequest {
            destination: Some("example.test".to_string()),
            destination_ip: Some("198.51.100.7".to_string()),
            interface: Some("eth0".to_string()),
            ..Default::default()
        })
        .unwrap();

        assert_eq!(
            spec.address,
            Some(TargetAddress::Ip(IpAddr::V4(Ipv4Addr::new(
                198, 51, 100, 7
            ))))
        );
        assert_eq!(spec.interface.as_deref(), Some("eth0"));
    }

    #[test]
    fn destination_spec_records_resolved_host() {
        let ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10));
        let spec = DestinationSpec::from_request(&DestinationRequest {
            destination: Some("example.test".to_string()),
            resolved_destination: Some(ip),
            ..Default::default()
        })
        .unwrap();

        assert_eq!(
            spec.address,
            Some(TargetAddress::ResolvedHost {
                host: "example.test".to_string(),
                ip
            })
        );
        assert_eq!(spec.address.as_ref().unwrap().to_string(), "203.0.113.10");
    }
}
