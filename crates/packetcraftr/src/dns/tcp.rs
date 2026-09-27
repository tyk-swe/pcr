// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Bounded DNS-over-TCP framing; callers authorize destinations and validate responses.

use packetcraftr_netio::tcp::{self, Provider, Stream};
use std::fmt;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;
use std::time::{Duration, SystemTime};

use bytes::Bytes;
use packetcraftr_core::budget::{Cancellation, Cancelled, Deadline, Interrupted};
use packetcraftr_core::error::{Classification, Classified, Kind, Source};
use thiserror::Error as ThisError;

pub const LENGTH_PREFIX_BYTES: usize = 2;

#[derive(Clone, Copy, Debug)]
pub struct Request<'a> {
    pub endpoint: SocketAddr,
    /// Exact DNS message, without the TCP length prefix.
    pub query: &'a [u8],
    pub timeout: Duration,
    pub cancellation: Option<&'a Cancellation>,
    /// Maximum accepted DNS message bytes, excluding the prefix.
    pub max_message_bytes: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Phase {
    Connect,
    Write,
    ReadPrefix,
    ReadMessage,
}

impl fmt::Display for Phase {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Connect => "connect",
            Self::Write => "write",
            Self::ReadPrefix => "read_prefix",
            Self::ReadMessage => "read_message",
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Category {
    Cancelled,
    Request,
    Unsupported,
    Timeout,
    Network,
    Framing,
}

#[derive(Clone, Debug, ThisError)]
#[non_exhaustive]
pub enum Error {
    #[error(transparent)]
    Cancelled(#[from] Cancelled),
    #[error("DNS-over-TCP system I/O is unavailable: {message}")]
    Unsupported { message: String },
    #[error("DNS-over-TCP timeout {value:?} is invalid; it must be non-zero")]
    InvalidTimeout { value: Duration },
    #[error("DNS-over-TCP query must not be empty")]
    EmptyQuery,
    #[error("DNS-over-TCP query is {actual} bytes; maximum is {maximum}")]
    QueryTooLarge { actual: usize, maximum: usize },
    #[error("DNS-over-TCP message limit {value} is invalid; expected 1..={maximum}")]
    InvalidMessageLimit { value: usize, maximum: usize },
    #[error("DNS-over-TCP deadline overflowed for timeout {value:?}")]
    DeadlineOverflow { value: Duration },
    #[error("DNS-over-TCP deadline expired during {phase} after {transferred} phase byte(s)")]
    Timeout { phase: Phase, transferred: usize },
    #[error("DNS-over-TCP connection to {endpoint} failed: {message}")]
    Connect {
        endpoint: SocketAddr,
        message: String,
        #[source]
        source: Option<Source>,
    },
    #[error(
        "DNS-over-TCP could not configure the {phase} timeout after {transferred} phase byte(s)"
    )]
    ConfigureTimeout {
        phase: Phase,
        transferred: usize,
        #[source]
        source: Source,
    },
    #[error("DNS-over-TCP query write stopped after {written} of {expected} bytes: {message}")]
    Write {
        written: usize,
        expected: usize,
        message: String,
        #[source]
        source: Option<Source>,
    },
    #[error("DNS-over-TCP {phase} failed: {message}")]
    Read {
        phase: Phase,
        message: String,
        #[source]
        source: Option<Source>,
    },
    #[error(
        "DNS-over-TCP response prefix ended after {actual} of {} bytes",
        LENGTH_PREFIX_BYTES
    )]
    IncompletePrefix { actual: usize },
    #[error("DNS-over-TCP response declared a zero-length DNS message")]
    ZeroLength,
    #[error("DNS-over-TCP response declared {declared} bytes; maximum is {maximum}")]
    MessageTooLarge { declared: usize, maximum: usize },
    #[error("DNS-over-TCP response body ended after {actual} of {declared} declared bytes")]
    IncompleteMessage { declared: usize, actual: usize },
}

impl Error {
    /// An exhaustive match, so a new variant is a compile error rather than a silent request fault.
    #[must_use]
    pub const fn category(&self) -> Category {
        match self {
            Self::Cancelled(_) => Category::Cancelled,
            Self::Unsupported { .. } => Category::Unsupported,
            Self::InvalidTimeout { .. }
            | Self::EmptyQuery
            | Self::QueryTooLarge { .. }
            | Self::InvalidMessageLimit { .. }
            | Self::DeadlineOverflow { .. } => Category::Request,
            Self::Timeout { .. } => Category::Timeout,
            Self::Connect { .. }
            | Self::ConfigureTimeout { .. }
            | Self::Write { .. }
            | Self::Read { .. } => Category::Network,
            Self::IncompletePrefix { .. }
            | Self::ZeroLength
            | Self::MessageTooLarge { .. }
            | Self::IncompleteMessage { .. } => Category::Framing,
        }
    }

    #[must_use]
    pub const fn query_bytes_written(&self, framed_query_bytes: usize) -> usize {
        match self {
            Self::Timeout {
                phase: Phase::Write,
                transferred,
            }
            | Self::ConfigureTimeout {
                phase: Phase::Write,
                transferred,
                ..
            } => *transferred,
            Self::Write { written, .. } => *written,
            Self::Timeout {
                phase: Phase::ReadPrefix | Phase::ReadMessage,
                ..
            }
            | Self::ConfigureTimeout {
                phase: Phase::ReadPrefix | Phase::ReadMessage,
                ..
            }
            | Self::Read { .. }
            | Self::IncompletePrefix { .. }
            | Self::ZeroLength
            | Self::MessageTooLarge { .. }
            | Self::IncompleteMessage { .. } => framed_query_bytes,
            Self::Cancelled(_)
            | Self::Unsupported { .. }
            | Self::InvalidTimeout { .. }
            | Self::EmptyQuery
            | Self::QueryTooLarge { .. }
            | Self::InvalidMessageLimit { .. }
            | Self::DeadlineOverflow { .. }
            | Self::Timeout {
                phase: Phase::Connect,
                ..
            }
            | Self::Connect { .. }
            | Self::ConfigureTimeout {
                phase: Phase::Connect,
                ..
            } => 0,
        }
    }
}

impl Classified for Error {
    fn classification(&self) -> Classification {
        match self.category() {
            Category::Cancelled => Cancelled.classification(),
            Category::Request => Classification::new(
                "internal.dns_tcp_request",
                Kind::Internal,
                Some("submit a non-empty bounded DNS query with a finite remaining timeout"),
            ),
            Category::Unsupported => Classification::new(
                "capability.dns_tcp",
                Kind::Capability,
                Some(
                    "enable native DNS-over-TCP or provide a TCP-capable executor, and remove incompatible packet-route overrides",
                ),
            ),
            Category::Timeout => Classification::new(
                "io.dns_tcp_timeout",
                Kind::Io,
                Some("retry within the finite DNS attempt budget or increase its timeout"),
            ),
            Category::Network => Classification::new(
                "io.dns_tcp",
                Kind::Io,
                Some("inspect the authorized DNS server TCP endpoint and retry"),
            ),
            Category::Framing => Classification::new(
                "packet.dns_tcp_frame",
                Kind::Packet,
                Some("treat the incomplete or oversized DNS-over-TCP response as invalid"),
            ),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Response {
    pub peer_address: SocketAddr,
    pub local_address: SocketAddr,
    pub sent_at: SystemTime,
    pub received_at: SystemTime,
    pub elapsed: Duration,
    pub latency: Duration,
    pub bytes_written: usize,
    /// One exact DNS-over-TCP frame, including its two-byte prefix.
    pub frame: Bytes,
}

/// A cancelled or expired wait returns while a stalled connect keeps its worker slot until cleanup.
pub fn query<P>(request: Request<'_>, provider: Arc<P>) -> Result<Response, Error>
where
    P: Provider<Stream: 'static> + 'static,
{
    query_with_clock(request, provider, Instant::now)
}

fn query_with_clock<P>(
    request: Request<'_>,
    connector: Arc<P>,
    now: impl Fn() -> Instant,
) -> Result<Response, Error>
where
    P: Provider<Stream: 'static> + 'static,
{
    let maximum = usize::from(u16::MAX);
    if request.timeout.is_zero() {
        return Err(Error::InvalidTimeout {
            value: request.timeout,
        });
    }
    if request.query.is_empty() {
        return Err(Error::EmptyQuery);
    }
    let query_length = u16::try_from(request.query.len()).map_err(|_| Error::QueryTooLarge {
        actual: request.query.len(),
        maximum,
    })?;
    if !(1..=maximum).contains(&request.max_message_bytes) {
        return Err(Error::InvalidMessageLimit {
            value: request.max_message_bytes,
            maximum,
        });
    }

    let started = now();
    let deadline = started
        .checked_add(request.timeout)
        .ok_or(Error::DeadlineOverflow {
            value: request.timeout,
        })?;
    let connect_timeout = remaining(deadline, now(), Phase::Connect, 0)?;
    let connect_deadline =
        Deadline::new(connect_timeout).with_cancellation(request.cancellation.cloned());
    let mut pending = tcp::start_connect(connector, request.endpoint, &connect_deadline)
        .map_err(|source| map_connect_error(request.endpoint, source))?;
    let outcome = pending
        .wait(&connect_deadline)
        .map_err(|source| map_connect_error(request.endpoint, source))?;
    packetcraftr_netio::deadline::remaining(&connect_deadline).map_err(|interrupted| {
        match interrupted {
            Interrupted::Cancelled(cancelled) => Error::Cancelled(cancelled),
            _ => Error::Timeout {
                phase: Phase::Connect,
                transferred: 0,
            },
        }
    })?;
    remaining(deadline, now(), Phase::Connect, 0)?;
    let mut stream = outcome
        .ok_or(Error::Timeout {
            phase: Phase::Connect,
            transferred: 0,
        })?
        .result
        .map_err(|source| map_connect_error(request.endpoint, source))?;
    let peer_address = stream.peer_addr().map_err(|source| Error::Connect {
        endpoint: request.endpoint,
        message: "peer socket inspection failed".to_owned(),
        source: Some(Source::new(source)),
    })?;
    if peer_address != request.endpoint {
        return Err(Error::Connect {
            endpoint: request.endpoint,
            message: format!("connected peer changed to {peer_address}"),
            source: None,
        });
    }
    let local_address = stream.local_addr().map_err(|source| Error::Connect {
        endpoint: request.endpoint,
        message: "local socket inspection failed".to_owned(),
        source: Some(Source::new(source)),
    })?;

    let expected_write =
        LENGTH_PREFIX_BYTES
            .checked_add(request.query.len())
            .ok_or(Error::QueryTooLarge {
                actual: request.query.len(),
                maximum,
            })?;
    let mut query_frame = Vec::with_capacity(expected_write);
    query_frame.extend_from_slice(&query_length.to_be_bytes());
    query_frame.extend_from_slice(request.query);
    let mut bytes_written = 0usize;
    write_exact(
        &mut stream,
        &query_frame,
        deadline,
        expected_write,
        &mut bytes_written,
        &now,
    )?;
    let sent = now();
    let sent_at = SystemTime::now();

    let mut response_prefix = [0u8; LENGTH_PREFIX_BYTES];
    let prefix_read = read_exact(
        &mut stream,
        &mut response_prefix,
        deadline,
        Phase::ReadPrefix,
        &now,
    )?;
    if prefix_read != LENGTH_PREFIX_BYTES {
        return Err(Error::IncompletePrefix {
            actual: prefix_read,
        });
    }
    let declared = usize::from(u16::from_be_bytes(response_prefix));
    if declared == 0 {
        return Err(Error::ZeroLength);
    }
    if declared > request.max_message_bytes {
        return Err(Error::MessageTooLarge {
            declared,
            maximum: request.max_message_bytes,
        });
    }

    let mut message = vec![0u8; declared];
    let message_read = read_exact(
        &mut stream,
        &mut message,
        deadline,
        Phase::ReadMessage,
        &now,
    )?;
    if message_read != declared {
        return Err(Error::IncompleteMessage {
            declared,
            actual: message_read,
        });
    }
    let received_at = SystemTime::now();
    let capacity = declared
        .checked_add(LENGTH_PREFIX_BYTES)
        .ok_or(Error::MessageTooLarge {
            declared,
            maximum: request.max_message_bytes,
        })?;
    let mut frame = Vec::with_capacity(capacity);
    frame.extend_from_slice(&response_prefix);
    frame.extend_from_slice(&message);
    let completed = now();
    if completed >= deadline {
        return Err(Error::Timeout {
            phase: Phase::ReadMessage,
            transferred: declared,
        });
    }
    Ok(Response {
        peer_address,
        local_address,
        sent_at,
        received_at,
        elapsed: completed.duration_since(started),
        latency: completed.duration_since(sent),
        bytes_written,
        frame: Bytes::from(frame),
    })
}

fn remaining(
    deadline: Instant,
    now: Instant,
    phase: Phase,
    transferred: usize,
) -> Result<Duration, Error> {
    deadline
        .checked_duration_since(now)
        .filter(|remaining| !remaining.is_zero())
        .ok_or(Error::Timeout { phase, transferred })
}

fn map_connect_error(endpoint: SocketAddr, error: packetcraftr_netio::tcp::Error) -> Error {
    use packetcraftr_netio::tcp::Error as TcpError;

    let timeout = Error::Timeout {
        phase: Phase::Connect,
        transferred: 0,
    };
    let source = match error {
        TcpError::Cancelled(cancelled) => return Error::Cancelled(cancelled),
        TcpError::Socket(source) if is_timeout(&source) => return timeout,
        TcpError::DeadlineExceeded => return timeout,
        TcpError::Socket(source) => Source::new(source),
        error => Source::new(error),
    };
    Error::Connect {
        endpoint,
        message: "the socket could not be opened".to_owned(),
        source: Some(source),
    }
}

fn write_exact<S: Stream>(
    stream: &mut S,
    mut bytes: &[u8],
    deadline: Instant,
    expected: usize,
    written: &mut usize,
    now: &impl Fn() -> Instant,
) -> Result<(), Error> {
    while !bytes.is_empty() {
        let timeout = remaining(deadline, now(), Phase::Write, *written)?;
        stream
            .set_write_timeout(Some(timeout))
            .map_err(|source| Error::ConfigureTimeout {
                phase: Phase::Write,
                transferred: *written,
                source: Source::new(source),
            })?;
        match stream.write(bytes) {
            Ok(0) => {
                return Err(Error::Write {
                    written: *written,
                    expected,
                    message: "peer accepted zero bytes".to_owned(),
                    source: None,
                });
            }
            Ok(count) => {
                *written = written.checked_add(count).ok_or(Error::Write {
                    written: *written,
                    expected,
                    message: "byte accounting overflowed".to_owned(),
                    source: None,
                })?;
                bytes = bytes.get(count..).ok_or(Error::Write {
                    written: *written,
                    expected,
                    message: "socket reported more bytes than were submitted".to_owned(),
                    source: None,
                })?;
            }
            Err(source) if source.kind() == io::ErrorKind::Interrupted => {}
            Err(source) if is_timeout(&source) => {
                return Err(Error::Timeout {
                    phase: Phase::Write,
                    transferred: *written,
                });
            }
            Err(source) => {
                return Err(Error::Write {
                    written: *written,
                    expected,
                    message: "the socket write failed".to_owned(),
                    source: Some(Source::new(source)),
                });
            }
        }
    }
    Ok(())
}

fn read_exact<S: Stream>(
    stream: &mut S,
    bytes: &mut [u8],
    deadline: Instant,
    phase: Phase,
    now: &impl Fn() -> Instant,
) -> Result<usize, Error> {
    let mut read = 0usize;
    while read < bytes.len() {
        let timeout = remaining(deadline, now(), phase, read)?;
        stream
            .set_read_timeout(Some(timeout))
            .map_err(|source| Error::ConfigureTimeout {
                phase,
                transferred: read,
                source: Source::new(source),
            })?;
        let tail = bytes.get_mut(read..).ok_or(Error::Read {
            phase,
            message: "read accounting exceeded the destination buffer".to_owned(),
            source: None,
        })?;
        match stream.read(tail) {
            Ok(0) => break,
            Ok(count) => {
                read = read.checked_add(count).ok_or(Error::Read {
                    phase,
                    message: "byte accounting overflowed".to_owned(),
                    source: None,
                })?;
            }
            Err(source) if source.kind() == io::ErrorKind::Interrupted => {}
            Err(source) if is_timeout(&source) => {
                return Err(Error::Timeout {
                    phase,
                    transferred: read,
                });
            }
            Err(source) => {
                return Err(Error::Read {
                    phase,
                    message: "the socket read failed".to_owned(),
                    source: Some(Source::new(source)),
                });
            }
        }
    }
    let _ = remaining(deadline, now(), phase, read)?;
    Ok(read)
}

fn is_timeout(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
    )
}

#[cfg(test)]
mod tests;
