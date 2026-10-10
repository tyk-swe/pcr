// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Evidence from bounded application I/O, including partial transfers.

use std::io;
use std::net::SocketAddr;

use bytes::Bytes;
use packetcraftr_core::budget::{Deadline, Interrupted};

/// Checks numeric peer identity without treating IPv6 flow information or an
/// irrelevant non-link-local unicast scope ID as part of the peer address.
/// IPv4-mapped addresses identify the same IPv4 peer. Link-local and multicast
/// scopes remain exact; canonical addresses and ports always remain exact.
pub fn same_peer(expected: SocketAddr, actual: SocketAddr) -> bool {
    let expected = socket_endpoint(expected);
    let actual = socket_endpoint(actual);
    if expected.ip() != actual.ip() || expected.port() != actual.port() {
        return false;
    }
    match (expected, actual) {
        (SocketAddr::V6(expected), SocketAddr::V6(actual)) => {
            expected.scope_id() == actual.scope_id()
        }
        _ => true,
    }
}

/// Selects the native address family for mapped IPv4 and removes irrelevant
/// scope IDs before socket setup. Native IPv6 flow information is preserved.
pub(crate) fn socket_endpoint(mut endpoint: SocketAddr) -> SocketAddr {
    if let SocketAddr::V6(address) = &mut endpoint {
        if let Some(ip) = address.ip().to_ipv4_mapped() {
            return SocketAddr::from((ip, address.port()));
        }
        if !address.ip().is_unicast_link_local() && !address.ip().is_multicast() {
            address.set_scope_id(0);
        }
    }
    endpoint
}

/// Application bytes transferred before the exchange stopped.
#[derive(Debug)]
pub struct Exchange {
    pub response: Bytes,
    pub bytes_sent: usize,
    pub outcome: Outcome,
}

#[derive(Debug)]
pub enum Outcome {
    Complete,
    Eof,
    /// The receive boundary was reached; no additional bytes were read.
    Truncated,
    TimedOut,
    Cancelled,
    Failed(io::Error),
}

impl Outcome {
    pub(crate) fn interrupted(source: Interrupted) -> Self {
        match source {
            Interrupted::Cancelled(_) => Self::Cancelled,
            _ => Self::TimedOut,
        }
    }
}

pub(crate) fn timeout(deadline: &Deadline) -> Result<std::time::Duration, Outcome> {
    crate::deadline::remaining(deadline)
        .map(|remaining| remaining.min(crate::deadline::POLL_INTERVAL))
        .map_err(Outcome::interrupted)
}

pub(crate) fn retryable(source: &io::Error) -> bool {
    matches!(
        source.kind(),
        io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
    )
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv6Addr, SocketAddrV6};

    use super::*;

    #[test]
    fn socket_setup_clears_only_irrelevant_scopes_without_changing_flow_information() {
        for (ip, scope) in [
            ("::1", 0),
            ("2001:db8::1", 0),
            ("fe80::1", 7),
            ("ff02::1", 7),
        ] {
            let ip = ip.parse().unwrap();
            let endpoint = SocketAddr::V6(SocketAddrV6::new(ip, 80, 123, 7));
            let expected = SocketAddr::V6(SocketAddrV6::new(ip, 80, 123, scope));
            assert_eq!(socket_endpoint(endpoint), expected);
            assert!(same_peer(endpoint, expected));
        }
        let ipv4 = "192.0.2.1:80".parse().unwrap();
        assert_eq!(socket_endpoint(ipv4), ipv4);
        let mapped = SocketAddr::V6(SocketAddrV6::new(
            "::ffff:192.0.2.1".parse().unwrap(),
            80,
            123,
            7,
        ));
        assert_eq!(socket_endpoint(mapped), ipv4);
        assert!(same_peer(mapped, ipv4));
        assert!(same_peer(ipv4, mapped));
        assert!(!same_peer(mapped, "192.0.2.2:80".parse().unwrap()));
        assert!(!same_peer(mapped, "192.0.2.1:81".parse().unwrap()));
    }

    #[test]
    fn peer_identity_ignores_flow_information_but_preserves_multicast_scopes() {
        let expected = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 80, 123, 7));
        let actual = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 80, 456, 0));
        assert!(same_peer(expected, actual));
        let expected = "[ff02::1%7]:80".parse().unwrap();
        assert!(same_peer(expected, "[ff02::1%7]:80".parse().unwrap()));
        assert!(!same_peer(expected, "[ff02::1%8]:80".parse().unwrap()));
        assert!(!same_peer(expected, "[ff02::1%7]:81".parse().unwrap()));
        assert!(!same_peer(expected, "[ff02::2%7]:80".parse().unwrap()));
        assert!(same_peer(
            "127.0.0.1:80".parse().unwrap(),
            "[::ffff:127.0.0.1]:80".parse().unwrap()
        ));
        assert!(!same_peer(
            "127.0.0.1:80".parse().unwrap(),
            "[::127.0.0.1]:80".parse().unwrap()
        ));
    }
}
