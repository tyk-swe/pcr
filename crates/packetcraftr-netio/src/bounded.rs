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
