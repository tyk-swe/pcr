// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::IpAddr;

use super::error::{SpecError, SpecResult};

use crate::domain::request::IpRequest;

use super::fragment::FragmentSpec;
use super::utils::parse_ip_address;

#[derive(Debug, Clone, Default)]
pub(crate) struct IpSpec {
    pub source: Option<IpAddr>,
    pub destination: Option<IpAddr>,
    pub prefer_ipv6: Option<bool>,
    pub ttl: Option<u8>,
    pub tos: Option<u8>,
    pub identification: Option<u16>,
    pub fragmentation: FragmentSpec,
}

impl IpSpec {
    pub(crate) fn from_request(request: &IpRequest) -> SpecResult<Option<Self>> {
        if request.prefer_ipv6.unwrap_or(false) && request.prefer_ipv4.unwrap_or(false) {
            return Err(SpecError::PreferIpv4AndIpv6Conflict);
        }

        let prefer_ipv6 = request.prefer_ipv6_setting();

        let source = request
            .source_ip
            .as_ref()
            .map(|s| parse_ip_address(s))
            .transpose()?;
        let destination = request
            .destination_ip
            .as_ref()
            .map(|s| parse_ip_address(s))
            .transpose()?;

        let spec = Self {
            source,
            destination,
            prefer_ipv6,
            ttl: request.ttl,
            tos: request.tos,
            identification: request.identification,
            fragmentation: FragmentSpec::from_request(&request.fragment),
        };

        if spec.is_effectively_empty() {
            Ok(None)
        } else {
            Ok(Some(spec))
        }
    }

    fn is_effectively_empty(&self) -> bool {
        self.source.is_none()
            && self.destination.is_none()
            && self.prefer_ipv6.is_none()
            && self.ttl.is_none()
            && self.tos.is_none()
            && self.identification.is_none()
            && self.fragmentation.is_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::request::{FragmentProfile, FragmentRequest};
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    #[test]
    fn ip_spec_from_empty_request_returns_none() {
        assert!(IpSpec::from_request(&IpRequest::default())
            .unwrap()
            .is_none());
    }

    #[test]
    fn ip_spec_from_request_parses_addresses_and_options() {
        let spec = IpSpec::from_request(&IpRequest {
            source_ip: Some("192.0.2.1".to_string()),
            destination_ip: Some("198.51.100.2".to_string()),
            ttl: Some(64),
            tos: Some(16),
            identification: Some(99),
            ..Default::default()
        })
        .unwrap()
        .unwrap();

        assert_eq!(spec.source, Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))));
        assert_eq!(
            spec.destination,
            Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 2)))
        );
        assert_eq!(spec.ttl, Some(64));
        assert_eq!(spec.tos, Some(16));
        assert_eq!(spec.identification, Some(99));
    }

    #[test]
    fn ip_spec_from_request_keeps_prefer_ipv6_false() {
        let spec = IpSpec::from_request(&IpRequest {
            prefer_ipv4: Some(true),
            ..Default::default()
        })
        .unwrap()
        .unwrap();

        assert_eq!(spec.prefer_ipv6, Some(false));
    }

    #[test]
    fn ip_spec_from_request_rejects_conflicting_preferences() {
        let err = IpSpec::from_request(&IpRequest {
            prefer_ipv6: Some(true),
            prefer_ipv4: Some(true),
            ..Default::default()
        })
        .unwrap_err();

        assert!(matches!(err, SpecError::PreferIpv4AndIpv6Conflict));
    }

    #[test]
    fn ip_spec_from_request_includes_ipv6_address() {
        let spec = IpSpec::from_request(&IpRequest {
            destination_ip: Some("2001:db8::1".to_string()),
            ..Default::default()
        })
        .unwrap()
        .unwrap();

        assert_eq!(
            spec.destination,
            Some(IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1)))
        );
    }

    #[test]
    fn ip_spec_from_request_includes_fragment_spec() {
        let spec = IpSpec::from_request(&IpRequest {
            fragment: FragmentRequest {
                profile: Some(FragmentProfile::Overlap),
                ..Default::default()
            },
            ..Default::default()
        })
        .unwrap()
        .unwrap();

        assert!(spec.fragmentation.overlap);
        assert_eq!(spec.fragmentation.profile, Some(FragmentProfile::Overlap));
    }
}
