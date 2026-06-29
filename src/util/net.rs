// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::{IpAddr, SocketAddr, ToSocketAddrs};

use thiserror::Error;

pub type Result<T> = std::result::Result<T, ResolveHostnameError>;

#[derive(Debug, Error)]
pub enum ResolveHostnameError {
    #[error("resolve hostname failed for '{host}'")]
    LookupFailed {
        host: String,
        #[source]
        source: std::io::Error,
    },
    #[error("hostname '{host}' did not resolve to any addresses")]
    NoAddresses { host: String },
}

pub fn resolve_hostname(host: &str, prefer_ipv6: Option<bool>) -> Result<IpAddr> {
    resolve_target_ip(host, prefer_ipv6)
}

pub fn resolve_target_ip(target: &str, prefer_ipv6: Option<bool>) -> Result<IpAddr> {
    Ok(resolve_target_socket_addr(target, 0, prefer_ipv6)?.ip())
}

pub fn resolve_target_socket_addr(
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
