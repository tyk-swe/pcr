// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::{IpAddr, SocketAddr, ToSocketAddrs};

use thiserror::Error;

pub(crate) type Result<T> = std::result::Result<T, ResolveHostnameError>;

#[derive(Debug, Error)]
pub(crate) enum ResolveHostnameError {
    #[error("resolve hostname failed for '{host}'")]
    LookupFailed {
        host: String,
        #[source]
        source: std::io::Error,
    },
    #[error("hostname '{host}' did not resolve to any addresses")]
    NoAddresses { host: String },
}

pub(crate) fn resolve_target_ip(target: &str, prefer_ipv6: Option<bool>) -> Result<IpAddr> {
    Ok(resolve_target_socket_addr(target, 0, prefer_ipv6)?.ip())
}

pub(crate) fn resolve_target_socket_addr(
    target: &str,
    port: u16,
    prefer_ipv6: Option<bool>,
) -> Result<SocketAddr> {
    let target = target.trim();

    if target.is_empty() {
        return Err(ResolveHostnameError::NoAddresses {
            host: target.to_string(),
        });
    }

    let addresses = resolve_target_addresses(target, port)?;
    select_preferred_address(&addresses, prefer_ipv6).ok_or_else(|| {
        ResolveHostnameError::NoAddresses {
            host: target.to_string(),
        }
    })
}

fn resolve_target_addresses(target: &str, port: u16) -> Result<Vec<SocketAddr>> {
    let host = target.trim();

    if host.is_empty() {
        return Err(ResolveHostnameError::NoAddresses {
            host: host.to_string(),
        });
    }

    let addresses: Vec<SocketAddr> = (host, port)
        .to_socket_addrs()
        .map_err(|source| ResolveHostnameError::LookupFailed {
            host: host.to_string(),
            source,
        })?
        .collect();

    if addresses.is_empty() {
        return Err(ResolveHostnameError::NoAddresses {
            host: host.to_string(),
        });
    }

    Ok(addresses)
}

fn select_preferred_address(
    addresses: &[SocketAddr],
    prefer_ipv6: Option<bool>,
) -> Option<SocketAddr> {
    if let Some(prefer_v6) = prefer_ipv6 {
        if let Some(addr) = addresses.iter().find(|addr| {
            matches!(
                (prefer_v6, addr),
                (true, SocketAddr::V6(_)) | (false, SocketAddr::V4(_))
            )
        }) {
            return Some(*addr);
        }
    }

    addresses.first().copied()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn socket(ip: IpAddr, port: u16) -> SocketAddr {
        SocketAddr::new(ip, port)
    }

    #[test]
    fn select_preferred_address_honors_ipv4_preference() {
        let addresses = [
            socket(IpAddr::V6(Ipv6Addr::LOCALHOST), 53),
            socket(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)), 53),
        ];

        assert_eq!(
            select_preferred_address(&addresses, Some(false)),
            Some(addresses[1])
        );
    }

    #[test]
    fn select_preferred_address_honors_ipv6_preference() {
        let addresses = [
            socket(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)), 53),
            socket(IpAddr::V6("2001:db8::10".parse().unwrap()), 53),
        ];

        assert_eq!(
            select_preferred_address(&addresses, Some(true)),
            Some(addresses[1])
        );
    }

    #[test]
    fn select_preferred_address_falls_back_to_first_when_preferred_family_absent() {
        let addresses = [
            socket(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)), 53),
            socket(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 10)), 53),
        ];

        assert_eq!(
            select_preferred_address(&addresses, Some(true)),
            Some(addresses[0])
        );
    }

    #[test]
    fn select_preferred_address_returns_none_for_empty_input() {
        assert_eq!(select_preferred_address(&[], Some(true)), None);
    }

    #[test]
    fn resolve_target_socket_addr_rejects_blank_target_without_dns_lookup() {
        let err = resolve_target_socket_addr(" \t ", 80, None).unwrap_err();

        assert!(matches!(err, ResolveHostnameError::NoAddresses { host } if host.is_empty()));
    }
}
