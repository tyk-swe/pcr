// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Policy-authorized, peer-verified bounded TCP connections shared by socket workflows.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use packetcraftr_core::budget::{Deadline, Interrupted};
use packetcraftr_netio::bounded;
use packetcraftr_netio::tcp::{self, Stream as _};

use crate::policy::Policy;

pub(crate) struct Connected<S> {
    pub(crate) stream: tcp::Connection<S>,
    pub(crate) peer: SocketAddr,
    pub(crate) local: SocketAddr,
}

#[derive(Debug)]
pub(crate) enum ConnectError {
    Policy(crate::policy::Error),
    Tcp(tcp::Error),
    PeerChanged { actual: SocketAddr },
    PeerAddr(io::Error),
    LocalAddr(io::Error),
}

fn interrupted_tcp(interrupted: Interrupted) -> ConnectError {
    ConnectError::Tcp(match interrupted {
        Interrupted::Cancelled(cancelled) => tcp::Error::Cancelled(cancelled),
        _ => tcp::Error::DeadlineExceeded,
    })
}

pub(crate) fn verify_peer(expected: SocketAddr, actual: SocketAddr) -> Result<(), ConnectError> {
    if !bounded::same_peer(expected, actual) {
        return Err(ConnectError::PeerChanged { actual });
    }
    Ok(())
}

/// Authorizes `endpoint` (when `policy` is supplied), opens a bounded TCP
/// connection, verifies `bounded::same_peer`, re-checks `policy` on the
/// resolved peer, and inspects local/peer addresses.
pub(crate) fn connect<P>(
    provider: Arc<P>,
    policy: Option<&Policy>,
    endpoint: SocketAddr,
    deadline: &Deadline,
) -> Result<Connected<P::Stream>, ConnectError>
where
    P: tcp::Provider<Stream: 'static> + 'static,
{
    if let Some(policy) = policy {
        policy
            .authorize_destination(endpoint.ip())
            .map_err(ConnectError::Policy)?;
    }
    deadline.live_remaining().map_err(interrupted_tcp)?;
    let mut pending =
        tcp::start_connect(provider, endpoint, deadline).map_err(ConnectError::Tcp)?;
    let outcome = pending.wait(deadline).map_err(ConnectError::Tcp)?;
    deadline.live_remaining().map_err(interrupted_tcp)?;
    let stream = outcome
        .ok_or(ConnectError::Tcp(tcp::Error::DeadlineExceeded))?
        .result
        .map_err(ConnectError::Tcp)?;
    let peer = stream.peer_addr().map_err(ConnectError::PeerAddr)?;
    verify_peer(endpoint, peer)?;
    if let Some(policy) = policy {
        policy
            .authorize_destination(peer.ip())
            .map_err(ConnectError::Policy)?;
    }
    let local = stream.local_addr().map_err(ConnectError::LocalAddr)?;
    Ok(Connected {
        stream,
        peer,
        local,
    })
}
