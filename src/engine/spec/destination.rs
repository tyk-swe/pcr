// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use std::fmt;
use std::net::IpAddr;

use super::error::SpecResult;

use crate::engine::request::DestinationRequest;

use super::utils::parse_ip_address;

#[derive(Debug, Clone, Default)]
pub struct DestinationSpec {
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
                    (TargetAddress::Host(_), Some(ip)) => TargetAddress::Ip(ip),
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
pub enum TargetAddress {
    Ip(IpAddr),
    Host(String),
}

impl fmt::Display for TargetAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TargetAddress::Ip(addr) => write!(f, "{addr}"),
            TargetAddress::Host(host) => write!(f, "{host}"),
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

    #[test]
    fn parse_target_address_classifies_ips_and_hostnames() {
        for input in ["192.168.1.1", "127.0.0.1", "2001:db8::1", "::1"] {
            assert_eq!(
                parse_target_address(input).unwrap(),
                TargetAddress::Ip(input.parse::<IpAddr>().unwrap())
            );
        }

        for input in ["example.com", "localhost", "not-an-ip"] {
            assert_eq!(
                parse_target_address(input).unwrap(),
                TargetAddress::Host(input.to_string())
            );
        }
    }

    #[test]
    fn destination_spec_default_is_empty() {
        let spec = DestinationSpec::default();
        assert!(spec.address.is_none());
        assert!(spec.interface.is_none());
    }

    #[test]
    fn destination_spec_uses_resolved_hostname_address() {
        let request = DestinationRequest {
            destination: Some("example.test".to_string()),
            resolved_destination: Some("192.0.2.7".parse().unwrap()),
            ..Default::default()
        };

        let spec = DestinationSpec::from_request(&request).expect("destination spec");

        assert_eq!(
            spec.address,
            Some(TargetAddress::Ip("192.0.2.7".parse().unwrap()))
        );
    }

    #[test]
    fn destination_ip_overrides_resolved_hostname_address() {
        let request = DestinationRequest {
            destination: Some("example.test".to_string()),
            destination_ip: Some("198.51.100.10".to_string()),
            resolved_destination: Some("192.0.2.7".parse().unwrap()),
            ..Default::default()
        };

        let spec = DestinationSpec::from_request(&request).expect("destination spec");

        assert_eq!(
            spec.address,
            Some(TargetAddress::Ip("198.51.100.10".parse().unwrap()))
        );
    }

    #[test]
    fn target_address_display_matches_inner_value() {
        let cases = [
            (
                TargetAddress::Ip("192.168.1.1".parse().unwrap()),
                "192.168.1.1",
            ),
            (
                TargetAddress::Ip("2001:db8::1".parse().unwrap()),
                "2001:db8::1",
            ),
            (
                TargetAddress::Host("example.com".to_string()),
                "example.com",
            ),
        ];

        for (address, expected) in cases {
            assert_eq!(address.to_string(), expected);
        }
    }

    #[test]
    fn parse_target_address_rejects_empty_values() {
        for input in ["", "   "] {
            assert!(matches!(
                parse_target_address(input),
                Err(super::super::error::SpecError::EmptyTargetAddress)
            ));
        }
    }
}
