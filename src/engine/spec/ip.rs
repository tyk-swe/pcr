use std::net::IpAddr;

use super::error::{SpecError, SpecResult};

use crate::engine::request::IpRequest;

use super::fragment::FragmentSpec;
use super::utils::parse_ip_address;

#[derive(Debug, Clone, Default)]
pub struct IpSpec {
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
    use std::net::IpAddr;

    #[test]
    fn from_options_rejects_both_prefer_flags() {
        let options = IpRequest {
            prefer_ipv6: Some(true),
            prefer_ipv4: Some(true),
            ..Default::default()
        };
        let result = IpSpec::from_request(&options);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            SpecError::PreferIpv4AndIpv6Conflict
        ));
    }

    #[test]
    fn from_options_invalid_ip_address() {
        let options = IpRequest {
            source_ip: Some("invalid_ip".to_string()),
            ..Default::default()
        };
        let result = IpSpec::from_request(&options);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            SpecError::IpAddressParse { .. }
        ));
    }

    #[test]
    fn is_effectively_empty_false_with_source() {
        let spec = IpSpec {
            source: Some(IpAddr::V4("192.168.1.1".parse().unwrap())),
            ..Default::default()
        };
        assert!(!spec.is_effectively_empty());
    }

    #[test]
    fn is_effectively_empty_false_with_ttl() {
        let spec = IpSpec {
            ttl: Some(64),
            ..Default::default()
        };
        assert!(!spec.is_effectively_empty());
    }
}
