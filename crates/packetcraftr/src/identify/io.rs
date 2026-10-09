// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::SocketAddr;
use std::sync::Arc;

use packetcraftr_core::budget::Deadline;
use packetcraftr_core::document::service_probes::{Probe, Request};
use packetcraftr_core::error::Source;
use packetcraftr_netio::tcp::Stream as _;
use packetcraftr_netio::udp::Provider as _;
use packetcraftr_netio::{bounded, tcp, udp};

use super::{Endpoint, Error, IoOutcome, Transport};
use crate::policy::{Operation, Policy, SocketLimits, SocketOperation};
use crate::providers::{TcpProviders, UdpProviders};

pub(super) struct Reply {
    pub bytes: Vec<u8>,
    pub written: u64,
    pub outcome: IoOutcome,
    pub local: Option<SocketAddr>,
    pub peer: Option<SocketAddr>,
    pub diagnostic: Option<String>,
    pub source: Option<Source>,
}

impl Reply {
    fn failed(source: impl std::error::Error + Send + Sync + 'static) -> Self {
        Self {
            bytes: Vec::new(),
            written: 0,
            outcome: IoOutcome::Failed,
            local: None,
            peer: None,
            diagnostic: Some(source.to_string()),
            source: Some(Source::new(source)),
        }
    }

    fn exchanged(exchange: bounded::Exchange, local: SocketAddr, peer: SocketAddr) -> Self {
        let (outcome, source) = match exchange.outcome {
            bounded::Outcome::Complete => (IoOutcome::Complete, None),
            bounded::Outcome::Eof => (IoOutcome::Eof, None),
            bounded::Outcome::Truncated => (IoOutcome::Truncated, None),
            bounded::Outcome::TimedOut => (IoOutcome::TimedOut, None),
            bounded::Outcome::Cancelled => (IoOutcome::Cancelled, None),
            bounded::Outcome::Failed(source) => (IoOutcome::Failed, Some(Source::new(source))),
        };
        Self {
            bytes: exchange.response.to_vec(),
            written: exchange.bytes_sent as u64,
            outcome,
            local: Some(local),
            peer: Some(peer),
            diagnostic: source.as_ref().map(ToString::to_string),
            source,
        }
    }

    fn tcp_failed(source: tcp::Error) -> Self {
        let outcome = match &source {
            tcp::Error::Cancelled(_) => IoOutcome::Cancelled,
            tcp::Error::DeadlineExceeded => IoOutcome::TimedOut,
            tcp::Error::Socket(source)
                if matches!(
                    source.kind(),
                    std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
                ) =>
            {
                IoOutcome::TimedOut
            }
            _ => IoOutcome::Failed,
        };
        Self {
            outcome,
            ..Self::failed(source)
        }
    }

    fn udp_failed(source: udp::Error) -> Self {
        let outcome = match &source {
            udp::Error::Interrupted(packetcraftr_core::budget::Interrupted::Cancelled(_)) => {
                IoOutcome::Cancelled
            }
            udp::Error::Interrupted(_) => IoOutcome::TimedOut,
            udp::Error::Socket(source)
                if matches!(
                    source.kind(),
                    std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
                ) =>
            {
                IoOutcome::TimedOut
            }
            _ => IoOutcome::Failed,
        };
        Self {
            outcome,
            ..Self::failed(source)
        }
    }
}

/// This wrapper performs authorization in the connect worker immediately
/// before the provider call, including when it waited in the worker queue.
struct AuthorizedTcp<P> {
    providers: Arc<P>,
    policy: Arc<Policy>,
}

impl<P: TcpProviders> tcp::Provider for AuthorizedTcp<P> {
    type Stream = <P::Tcp as tcp::Provider>::Stream;

    fn connect(
        &self,
        endpoint: SocketAddr,
        deadline: &Deadline,
    ) -> Result<Self::Stream, tcp::Error> {
        self.policy
            .authorize_destination(endpoint.ip())
            .map_err(|source| std::io::Error::new(std::io::ErrorKind::PermissionDenied, source))?;
        self.providers.tcp().connect(endpoint, deadline)
    }
}

pub(super) fn exchange<P: TcpProviders + UdpProviders>(
    providers: &Arc<P>,
    policy: &Arc<Policy>,
    endpoint: Endpoint,
    probe: &Probe,
    request: &[u8],
    max_response: usize,
    deadline: &Deadline,
) -> Result<Reply, Error> {
    match endpoint.transport {
        Transport::Tcp => tcp_exchange(
            providers,
            policy,
            endpoint.address,
            probe,
            request,
            max_response,
            deadline,
        ),
        Transport::Udp => {
            authorize_message(policy, endpoint.address, request.len())?;
            let reply =
                match providers
                    .udp()
                    .exchange(endpoint.address, request, max_response, deadline)
                {
                    Ok(reply) => reply,
                    Err(source) => return Ok(Reply::udp_failed(source)),
                };
            if reply.peer != endpoint.address {
                return Err(Error::Provider {
                    reason: "UDP reply changed the numeric peer".into(),
                });
            }
            Ok(Reply::exchanged(reply.exchange, reply.local, reply.peer))
        }
    }
}

fn authorize_message(policy: &Policy, endpoint: SocketAddr, bytes: usize) -> Result<(), Error> {
    let endpoints = [endpoint];
    let operation = SocketOperation::new(&endpoints, SocketLimits::new(0, 1, bytes as u64))
        .map_err(|source| Error::request(source.to_string()))?;
    policy.authorize(Operation::Socket(operation))?;
    Ok(())
}

fn tcp_exchange<P: TcpProviders>(
    providers: &Arc<P>,
    policy: &Arc<Policy>,
    endpoint: SocketAddr,
    probe: &Probe,
    request: &[u8],
    max_response: usize,
    deadline: &Deadline,
) -> Result<Reply, Error> {
    policy.authorize_destination(endpoint.ip())?;
    let connector = Arc::new(AuthorizedTcp {
        providers: Arc::clone(providers),
        policy: Arc::clone(policy),
    });
    let mut pending = match tcp::start_connect(connector, endpoint, deadline) {
        Ok(pending) => pending,
        Err(source) => return Ok(Reply::tcp_failed(source)),
    };
    let outcome = match pending.wait(deadline) {
        Ok(Some(outcome)) => outcome,
        Ok(None) => {
            return Ok(Reply {
                outcome: IoOutcome::TimedOut,
                ..Reply::failed(tcp::Error::DeadlineExceeded)
            });
        }
        Err(source) => return Ok(Reply::tcp_failed(source)),
    };
    let mut stream = match outcome.result {
        Ok(stream) => stream,
        Err(source) => return Ok(Reply::tcp_failed(source)),
    };
    let peer = match stream.peer_addr() {
        Ok(peer) => peer,
        Err(source) => return Ok(Reply::failed(source)),
    };
    if peer != endpoint {
        return Err(Error::Provider {
            reason: "TCP connection changed the numeric peer".into(),
        });
    }
    let local = match stream.local_addr() {
        Ok(local) => local,
        Err(source) => return Ok(Reply::failed(source)),
    };
    // No request byte is handed to the stream until the final peer and exact
    // application-byte declaration have both been authorized.
    if !request.is_empty() {
        authorize_message(policy, peer, request.len())?;
    }
    let exchange = match tcp::exchange(&mut stream, request, max_response, deadline, |bytes| {
        complete(probe, bytes)
    }) {
        Ok(exchange) => exchange,
        Err(source) => return Ok(Reply::tcp_failed(source)),
    };
    Ok(Reply::exchanged(exchange, local, peer))
}

fn complete(probe: &Probe, bytes: &[u8]) -> bool {
    match probe.request {
        Request::Banner {} => {
            bytes
                .split(|byte| *byte == b'\n')
                .any(|line| line.starts_with(b"SSH-") && line.ends_with(b"\r"))
                && bytes.ends_with(b"\n")
        }
        Request::HttpHead {} => bytes.windows(4).any(|window| window == b"\r\n\r\n"),
        Request::Dns { .. } => bytes.get(..2).is_some_and(|prefix| {
            bytes.len() >= 2 + usize::from(u16::from_be_bytes([prefix[0], prefix[1]]))
        }),
    }
}
