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
    deadline
        .live_remaining()
        .map(|remaining| remaining.min(crate::deadline::POLL_INTERVAL))
        .map_err(Outcome::interrupted)
}

/// Arms the socket's transfer timeout for one bounded slice and enforces the
/// deadline again after the timeout call returns.
pub(crate) fn prepare_transfer(
    deadline: &Deadline,
    set_timeout: impl FnOnce(Option<std::time::Duration>) -> io::Result<()>,
) -> Result<(), Outcome> {
    let wait = timeout(deadline)?;
    set_timeout(Some(wait)).map_err(Outcome::Failed)?;
    deadline.enforce().map_err(Outcome::interrupted)
}

pub(crate) fn retryable(source: &io::Error) -> bool {
    matches!(
        source.kind(),
        io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv6Addr, SocketAddrV6};

    fn v6(ip: Ipv6Addr, port: u16, scope_id: u32) -> SocketAddr {
        SocketAddrV6::new(ip, port, 0, scope_id).into()
    }

    fn v6_flow(ip: Ipv6Addr, port: u16, flowinfo: u32, scope_id: u32) -> SocketAddr {
        SocketAddrV6::new(ip, port, flowinfo, scope_id).into()
    }

    #[test]
    fn same_peer_requires_equal_canonical_address_and_port() {
        let peer: SocketAddr = "127.0.0.1:53".parse().unwrap();
        assert!(same_peer(peer, peer));
        assert!(!same_peer(peer, "127.0.0.1:54".parse().unwrap()));
        assert!(!same_peer(peer, "127.0.0.2:53".parse().unwrap()));
    }

    #[test]
    fn same_peer_treats_mapped_ipv4_as_the_ipv4_peer() {
        let mapped = v6("::ffff:127.0.0.1".parse().unwrap(), 53, 0);
        assert!(same_peer(mapped, "127.0.0.1:53".parse().unwrap()));
        assert!(!same_peer(mapped, "127.0.0.1:54".parse().unwrap()));
    }

    #[test]
    fn same_peer_does_not_treat_flow_information_as_identity() {
        let global: Ipv6Addr = "2001:db8::1".parse().unwrap();
        assert!(same_peer(
            v6_flow(global, 53, 0, 0),
            v6_flow(global, 53, 0x12345, 0)
        ));
        let link_local: Ipv6Addr = "fe80::1".parse().unwrap();
        assert!(same_peer(
            v6_flow(link_local, 53, 7, 2),
            v6_flow(link_local, 53, 9, 2)
        ));
        assert!(!same_peer(
            v6_flow(link_local, 53, 7, 1),
            v6_flow(link_local, 53, 7, 2)
        ));
    }

    #[test]
    fn socket_endpoint_preserves_native_flow_information() {
        let global: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let endpoint = socket_endpoint(v6_flow(global, 53, 0xabc, 4));
        let SocketAddr::V6(endpoint) = endpoint else {
            panic!("expected IPv6 endpoint, got {endpoint:?}");
        };
        assert_eq!(endpoint.flowinfo(), 0xabc);
        assert_eq!(endpoint.scope_id(), 0);
    }

    #[test]
    fn same_peer_ignores_scope_only_where_scope_is_irrelevant() {
        let global: Ipv6Addr = "2001:db8::1".parse().unwrap();
        assert!(same_peer(v6(global, 53, 0), v6(global, 53, 7)));
        let link_local: Ipv6Addr = "fe80::1".parse().unwrap();
        assert!(same_peer(v6(link_local, 53, 2), v6(link_local, 53, 2)));
        assert!(!same_peer(v6(link_local, 53, 1), v6(link_local, 53, 2)));
        let multicast: Ipv6Addr = "ff02::1".parse().unwrap();
        assert!(!same_peer(v6(multicast, 53, 1), v6(multicast, 53, 2)));
    }

    #[test]
    fn interrupted_maps_cancellation_apart_from_expiry() {
        use packetcraftr_core::budget::Cancelled;
        assert!(matches!(
            Outcome::interrupted(Interrupted::Cancelled(Cancelled)),
            Outcome::Cancelled
        ));
        let exceeded = Deadline::new(std::time::Duration::ZERO)
            .live_remaining()
            .unwrap_err();
        assert!(matches!(exceeded, Interrupted::Exceeded(_)));
        assert!(matches!(Outcome::interrupted(exceeded), Outcome::TimedOut));
    }

    #[test]
    fn prepare_transfer_fails_closed_on_expiry_and_timeout_errors() {
        use std::sync::{
            Arc,
            atomic::{AtomicU64, Ordering},
        };
        let live = Deadline::new(std::time::Duration::from_secs(5));
        let mut armed = None;
        assert!(
            prepare_transfer(&live, |timeout| {
                armed = Some(timeout);
                Ok(())
            })
            .is_ok()
        );
        assert_eq!(armed, Some(Some(crate::deadline::POLL_INTERVAL)));
        assert!(matches!(
            prepare_transfer(&live, |_| Err(io::Error::from(io::ErrorKind::InvalidInput))),
            Err(Outcome::Failed(_))
        ));
        let expired = Deadline::new(std::time::Duration::ZERO);
        assert!(matches!(
            prepare_transfer(&expired, |_| Ok(())),
            Err(Outcome::TimedOut)
        ));
        let advanced = Arc::new(AtomicU64::new(0));
        let clock = Arc::clone(&advanced);
        let origin = std::time::Instant::now();
        let parent = Deadline::with_time_source(std::time::Duration::from_secs(30), move || {
            origin + std::time::Duration::from_secs(clock.load(Ordering::SeqCst))
        });
        let caller =
            Deadline::new(std::time::Duration::from_secs(30)).with_parent(Some(Arc::new(parent)));
        let outcome = prepare_transfer(&caller, |_| {
            advanced.store(31, Ordering::SeqCst);
            Ok(())
        });
        assert!(matches!(outcome, Err(Outcome::TimedOut)), "{outcome:?}");
    }

    #[test]
    fn retryable_covers_only_transient_io_kinds() {
        for kind in [
            io::ErrorKind::Interrupted,
            io::ErrorKind::WouldBlock,
            io::ErrorKind::TimedOut,
        ] {
            assert!(retryable(&io::Error::from(kind)), "{kind:?}");
        }
        for kind in [
            io::ErrorKind::NotFound,
            io::ErrorKind::InvalidInput,
            io::ErrorKind::ConnectionReset,
            io::ErrorKind::PermissionDenied,
            io::ErrorKind::UnexpectedEof,
        ] {
            assert!(!retryable(&io::Error::from(kind)), "{kind:?}");
        }
    }
}
