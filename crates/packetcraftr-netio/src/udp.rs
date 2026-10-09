// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! One numeric, connected datagram exchange with bounded retained evidence.

use std::io;
use std::net::{SocketAddr, UdpSocket};

use bytes::Bytes;
use packetcraftr_core::budget::{Deadline, Interrupted};
use packetcraftr_core::error::{Classification, Classified, Kind};

use crate::bounded::{Exchange, Outcome, retryable, timeout};

pub const MAX_PAYLOAD_BYTES: usize = packetcraftr_core::document::udp_profiles::MAX_PAYLOAD_BYTES;
pub const MAX_RESPONSE_BYTES: usize = 65_535;

#[derive(Debug)]
pub struct Reply {
    pub peer: SocketAddr,
    pub local: SocketAddr,
    pub exchange: Exchange,
}

/// Sends one datagram to the exact numeric endpoint, without resolution,
/// retries, fallback, or accepting responses from a different peer.
/// Implementations must verify the connected peer before sending, obey the
/// deadline and byte bounds, and report every completed transfer. `Err` is
/// reserved for validation or setup failures before transmission; failures
/// after sending belong in [`Reply::exchange`] so byte accounting is retained.
pub trait Provider: Send + Sync {
    fn exchange(
        &self,
        endpoint: SocketAddr,
        request: &[u8],
        max_response: usize,
        deadline: &Deadline,
    ) -> Result<Reply, Error>;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct SystemProvider;

impl Provider for SystemProvider {
    fn exchange(
        &self,
        endpoint: SocketAddr,
        request: &[u8],
        max_response: usize,
        deadline: &Deadline,
    ) -> Result<Reply, Error> {
        if endpoint.port() == 0
            || request.len() > MAX_PAYLOAD_BYTES
            || max_response == 0
            || max_response > MAX_RESPONSE_BYTES
        {
            return Err(Error::Limit);
        }
        crate::deadline::remaining(deadline)?;
        let bind = if endpoint.is_ipv4() {
            SocketAddr::from(([0, 0, 0, 0], 0))
        } else {
            SocketAddr::from(([0u16; 8], 0))
        };
        let socket = UdpSocket::bind(bind)?;
        socket.connect(endpoint)?;
        let local = socket.local_addr()?;
        let peer = socket.peer_addr()?;
        if !crate::bounded::same_peer(endpoint, peer) {
            return Err(Error::Peer {
                expected: endpoint,
                actual: peer,
            });
        }
        let mut response = vec![0; max_response];
        let mut bytes_sent = 0;
        let mut bytes_read = 0;
        let outcome = 'exchange: {
            let wait = match timeout(deadline) {
                Ok(wait) => wait,
                Err(outcome) => break 'exchange outcome,
            };
            if let Err(source) = socket.set_write_timeout(Some(wait)) {
                break 'exchange Outcome::Failed(source);
            }
            if let Err(source) = deadline.enforce() {
                break 'exchange Outcome::interrupted(source);
            }
            // A single datagram send is never retried: a receive timeout must
            // not cause another transmission outside the caller's attempt budget.
            match socket.send(request) {
                Ok(count) if count <= request.len() => bytes_sent = count,
                Ok(_) => {
                    break 'exchange Outcome::Failed(io::Error::other(
                        "impossible UDP send length",
                    ));
                }
                Err(source) => break 'exchange Outcome::Failed(source),
            }
            if bytes_sent != request.len() {
                break 'exchange Outcome::Failed(io::ErrorKind::WriteZero.into());
            }
            loop {
                let wait = match timeout(deadline) {
                    Ok(wait) => wait,
                    Err(outcome) => break 'exchange outcome,
                };
                if let Err(source) = socket.set_read_timeout(Some(wait)) {
                    break 'exchange Outcome::Failed(source);
                }
                if let Err(source) = deadline.enforce() {
                    break 'exchange Outcome::interrupted(source);
                }
                match crate::platform::receive_datagram(&socket, &mut response) {
                    Ok((count, truncated)) => {
                        bytes_read = count;
                        if let Err(source) = crate::deadline::remaining(deadline) {
                            break 'exchange Outcome::interrupted(source);
                        }
                        break 'exchange if truncated {
                            Outcome::Truncated
                        } else {
                            Outcome::Complete
                        };
                    }
                    Err(source) if retryable(&source) => continue,
                    Err(source) => break 'exchange Outcome::Failed(source),
                }
            }
        };
        response.truncate(bytes_read);
        Ok(Reply {
            peer,
            local,
            exchange: Exchange {
                response: Bytes::from(response),
                bytes_sent,
                outcome,
            },
        })
    }
}

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    #[error(transparent)]
    Socket(#[from] io::Error),
    #[error(transparent)]
    Interrupted(#[from] Interrupted),
    #[error(
        "UDP exchange requires a nonzero port, a bounded payload, and 1..=65535 response bytes"
    )]
    Limit,
    #[error("UDP provider connected to {actual}, expected {expected}")]
    Peer {
        expected: SocketAddr,
        actual: SocketAddr,
    },
}

impl Classified for Error {
    fn classification(&self) -> Classification {
        match self {
            Self::Socket(_) => Classification::new("io.udp_exchange", Kind::Io, None),
            Self::Interrupted(source) => source.classification(),
            Self::Limit => Classification::new("cli.udp_exchange_limit", Kind::Usage, None),
            Self::Peer { .. } => Classification::new("io.udp_peer", Kind::Io, None),
        }
    }
}
