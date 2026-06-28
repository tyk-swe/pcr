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

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

    /// Returns true if resolving localhost yields at least one IPv6 address on this host.
    #[cfg(feature = "net_integration")]
    fn localhost_has_ipv6() -> bool {
        ("localhost", 0)
            .to_socket_addrs()
            .map(|mut iter| iter.any(|addr: SocketAddr| matches!(addr, SocketAddr::V6(_))))
            .unwrap_or(false)
    }

    #[test]
    fn resolve_hostname_trims_and_resolves_ip_literal() {
        let addr = resolve_hostname(" 127.0.0.1 ", None).unwrap();
        assert_eq!(addr, IpAddr::V4(Ipv4Addr::LOCALHOST));
    }

    #[test]
    fn resolve_hostname_rejects_empty_string() {
        assert!(resolve_hostname("", None).is_err());
    }

    #[cfg(feature = "net_integration")]
    #[ignore = "requires host resolver configuration"]
    #[test]
    fn resolve_hostname_prefers_ipv6_when_available() {
        let addr = resolve_hostname("localhost", Some(true)).unwrap();
        assert!(addr.is_loopback());
        if localhost_has_ipv6() {
            assert!(matches!(addr, IpAddr::V6(_)));
        }
    }

    #[test]
    fn resolve_hostname_with_ipv4_literal() {
        let addr = resolve_hostname("192.168.1.1", None).unwrap();
        assert_eq!(addr, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
    }

    #[test]
    fn resolve_hostname_with_ipv6_literal() {
        let addr = resolve_hostname("2001:db8::1", None).unwrap();
        assert_eq!(
            addr,
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1))
        );
    }

    #[test]
    fn resolve_hostname_ipv4_literal_ignores_preference() {
        // Even if we prefer IPv6, giving an IPv4 literal should return the IPv4 address
        let addr = resolve_hostname("192.168.1.1", Some(true)).unwrap();
        assert_eq!(addr, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
    }

    #[test]
    fn resolve_hostname_ipv6_literal_ignores_preference() {
        // Even if we prefer IPv4, giving an IPv6 literal should return the IPv6 address
        let addr = resolve_hostname("2001:db8::1", Some(false)).unwrap();
        assert_eq!(
            addr,
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1))
        );
    }

    #[test]
    fn resolve_hostname_fails_on_invalid_format() {
        let result = resolve_hostname("invalid/host", None);
        assert!(matches!(
            result,
            Err(ResolveHostnameError::LookupFailed { .. })
        ));
    }

    #[test]
    fn resolve_target_socket_addr_keeps_requested_port() {
        let addr = resolve_target_socket_addr("127.0.0.1", 4444, None).expect("socket addr");
        assert_eq!(addr, SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 4444));
    }

    #[test]
    fn select_preferred_address_uses_static_addresses() {
        let v4 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7)), 53);
        let v6 = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 53);
        let addresses = [v4, v6];

        assert_eq!(select_preferred_address(&addresses, Some(true)), Some(v6));
        assert_eq!(select_preferred_address(&addresses, Some(false)), Some(v4));
        assert_eq!(select_preferred_address(&addresses, None), Some(v4));
    }

    #[cfg(feature = "net_integration")]
    #[ignore = "requires host resolver configuration"]
    #[test]
    fn resolve_target_ip_prefers_ipv4_when_requested() {
        let addr = resolve_target_ip("localhost", Some(false)).expect("resolved localhost");
        if ("localhost", 0)
            .to_socket_addrs()
            .map(|mut iter| iter.any(|a| matches!(a, SocketAddr::V4(_))))
            .unwrap_or(false)
        {
            assert!(matches!(addr, IpAddr::V4(_)));
        }
    }

    #[cfg(feature = "net_integration")]
    #[ignore = "requires host resolver configuration"]
    #[test]
    fn resolve_target_socket_addr_prefers_ipv6_when_available() {
        let addr = resolve_target_socket_addr("localhost", 80, Some(true)).expect("socket addr");
        if localhost_has_ipv6() {
            assert!(matches!(addr, SocketAddr::V6(_)));
        }
    }
}
