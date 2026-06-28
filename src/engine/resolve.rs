// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::IpAddr;

use thiserror::Error;

use crate::engine::request::PacketRequest;

pub type ResolveResult<T> = std::result::Result<T, ResolveError>;

pub trait TargetResolver {
    fn resolve_target_ip(&self, target: &str, prefer_ipv6: Option<bool>) -> ResolveResult<IpAddr>;
}

#[derive(Debug, Error)]
pub enum ResolveError {
    #[error("resolve hostname failed: host='{host}': {message}")]
    HostnameResolution { host: String, message: String },
}

#[derive(Debug, Default, Clone, Copy)]
pub struct SystemTargetResolver;

impl TargetResolver for SystemTargetResolver {
    fn resolve_target_ip(&self, target: &str, prefer_ipv6: Option<bool>) -> ResolveResult<IpAddr> {
        crate::util::net::resolve_target_ip(target, prefer_ipv6).map_err(|err| {
            ResolveError::HostnameResolution {
                host: target.to_string(),
                message: err.to_string(),
            }
        })
    }
}

pub fn resolve_packet_request<R>(
    mut request: PacketRequest,
    resolver: &R,
) -> ResolveResult<PacketRequest>
where
    R: TargetResolver + ?Sized,
{
    if request.destination.destination_ip.is_none() {
        if let Some(target) = request.destination.destination.as_deref() {
            let trimmed = target.trim();
            if !trimmed.is_empty() && trimmed.parse::<IpAddr>().is_err() {
                let resolved = resolver.resolve_target_ip(trimmed, request.prefer_ipv6_hint())?;
                request.destination.resolved_destination = Some(resolved);
            }
        }
    }

    Ok(request)
}

#[cfg(any(test, feature = "test_utils"))]
pub mod test_utils {
    use super::*;

    #[derive(Debug, Clone)]
    pub struct StaticTargetResolver {
        address: Option<IpAddr>,
        error_message: Option<String>,
    }

    impl StaticTargetResolver {
        pub fn resolves_to(address: IpAddr) -> Self {
            Self {
                address: Some(address),
                error_message: None,
            }
        }

        pub fn fails_with(message: impl Into<String>) -> Self {
            Self {
                address: None,
                error_message: Some(message.into()),
            }
        }
    }

    impl TargetResolver for StaticTargetResolver {
        fn resolve_target_ip(
            &self,
            target: &str,
            _prefer_ipv6: Option<bool>,
        ) -> ResolveResult<IpAddr> {
            if let Some(address) = self.address {
                return Ok(address);
            }

            Err(ResolveError::HostnameResolution {
                host: target.to_string(),
                message: self
                    .error_message
                    .clone()
                    .unwrap_or_else(|| "static resolver failure".to_string()),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn static_resolver_populates_hostname_destination_without_dns() {
        let resolver =
            test_utils::StaticTargetResolver::resolves_to(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7)));
        let mut request = PacketRequest::default();
        request.destination.destination = Some("example.test".to_string());

        let resolved = resolve_packet_request(request, &resolver).expect("static resolve");

        assert_eq!(
            resolved.destination.resolved_destination,
            Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7)))
        );
    }

    #[test]
    fn static_resolver_is_not_used_for_ip_literals() {
        let resolver = test_utils::StaticTargetResolver::fails_with("must not be called");
        let mut request = PacketRequest::default();
        request.destination.destination = Some("192.0.2.8".to_string());

        let resolved = resolve_packet_request(request, &resolver).expect("literal skip");

        assert_eq!(resolved.destination.resolved_destination, None);
    }
}
