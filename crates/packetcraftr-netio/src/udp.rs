// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! One numeric, connected datagram exchange with bounded retained evidence.

use std::io;
use std::net::{SocketAddr, UdpSocket};

use bytes::Bytes;
use packetcraftr_core::budget::{Deadline, Interrupted};
use packetcraftr_core::error::{Classification, Classified, Kind};

use crate::bounded::{Exchange, Outcome, prepare_transfer, retryable};

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
        deadline.live_remaining()?;
        let destination = crate::bounded::socket_endpoint(endpoint);
        let bind = if destination.is_ipv4() {
            SocketAddr::from(([0, 0, 0, 0], 0))
        } else {
            SocketAddr::from(([0u16; 8], 0))
        };
        let socket = UdpSocket::bind(bind)?;
        socket.connect(destination)?;
        let local = socket.local_addr()?;
        let peer = socket.peer_addr()?;
        if !crate::bounded::same_peer(endpoint, peer) {
            return Err(Error::Peer {
                expected: endpoint,
                actual: peer,
            });
        }
        let mut response = vec![0; max_response + 1];
        let mut bytes_sent = 0;
        let mut bytes_read = 0;
        let outcome = 'exchange: {
            if let Err(outcome) = prepare_transfer(deadline, |wait| socket.set_write_timeout(wait))
            {
                break 'exchange outcome;
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
                if let Err(outcome) =
                    prepare_transfer(deadline, |wait| socket.set_read_timeout(wait))
                {
                    break 'exchange outcome;
                }
                match crate::platform::receive_datagram(&socket, &mut response) {
                    Ok((count, truncated)) => {
                        bytes_read = count.min(max_response);
                        if let Err(source) = deadline.live_remaining() {
                            break 'exchange Outcome::interrupted(source);
                        }
                        break 'exchange if truncated || count > max_response {
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    #[test]
    fn retained_udp_response_limit_is_exact() {
        for length in [0, 3, 4, 5, 64] {
            let server = UdpSocket::bind("127.0.0.1:0").unwrap();
            server
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let endpoint = server.local_addr().unwrap();
            let worker = std::thread::spawn(move || {
                let mut request = [0; 16];
                let (_, peer) = server.recv_from(&mut request).unwrap();
                server.send_to(&vec![7; length], peer).unwrap();
            });
            let reply = SystemProvider
                .exchange(
                    endpoint,
                    b"query",
                    4,
                    &Deadline::new(Duration::from_secs(2)),
                )
                .unwrap();
            worker.join().unwrap();
            assert_eq!(reply.exchange.response.len(), length.min(4));
            match reply.exchange.outcome {
                Outcome::Complete => assert!(length <= 4),
                Outcome::Truncated => assert!(length > 4),
                other => panic!("unexpected outcome: {other:?}"),
            }
        }
    }
}
