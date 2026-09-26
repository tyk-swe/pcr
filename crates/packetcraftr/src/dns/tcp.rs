// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Bounded DNS-over-TCP framing over an explicitly selected TCP provider.
//!
//! Callers authorize destinations and validate DNS responses. Each exchange
//! reads one declared response frame, then drops the connection.

use packetcraftr_netio::tcp::{Provider, Stream};
use std::fmt;
use std::io;
use std::net::SocketAddr;
use std::time::Instant;
use std::time::{Duration, SystemTime};

use bytes::Bytes;
use packetcraftr_core::error::{Classification, Classified, Kind, Source};
use thiserror::Error as ThisError;

/// Bytes in the DNS-over-TCP message-length prefix.
pub const LENGTH_PREFIX_BYTES: usize = 2;

/// One bounded DNS-over-TCP exchange request.
#[derive(Clone, Copy, Debug)]
pub struct Request<'a> {
    /// Already-authorized numeric DNS server endpoint.
    pub endpoint: SocketAddr,
    /// Exact DNS message, without the TCP length prefix.
    pub query: &'a [u8],
    /// Time remaining in the workflow attempt.
    pub timeout: Duration,
    /// Maximum accepted DNS message bytes, excluding the prefix.
    pub max_message_bytes: usize,
}

/// The socket phase in which a bounded operation failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Phase {
    Connect,
    /// Writing the prefixed DNS query.
    Write,
    /// Reading the two-byte response prefix.
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

/// The retry-relevant class of a DNS-over-TCP failure.
///
/// Every [`Error`] variant belongs to exactly one category, and the category
/// decides both the stable classification and how a workflow may react.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Category {
    /// The caller submitted a request that is not a runnable bounded exchange.
    Request,
    /// This build or route cannot execute DNS over TCP at all.
    Unsupported,
    /// The bounded attempt deadline expired during a socket phase.
    Timeout,
    /// A socket operation failed before an orderly response.
    Network,
    /// The peer's DNS-over-TCP framing was incomplete or oversized.
    Framing,
}

#[derive(Clone, Debug, ThisError)]
#[non_exhaustive]
pub enum Error {
    #[error("DNS-over-TCP system I/O is unavailable: {message}")]
    Unsupported { message: String },
    #[error("DNS-over-TCP timeout {value:?} is invalid; it must be non-zero")]
    InvalidTimeout { value: Duration },
    #[error("DNS-over-TCP query must not be empty")]
    EmptyQuery,
    /// The local query cannot be represented by the two-byte wire prefix.
    #[error("DNS-over-TCP query is {actual} bytes; maximum is {maximum}")]
    QueryTooLarge { actual: usize, maximum: usize },
    /// The response bound is not representable by DNS-over-TCP framing.
    #[error("DNS-over-TCP message limit {value} is invalid; expected 1..={maximum}")]
    InvalidMessageLimit { value: usize, maximum: usize },
    #[error("DNS-over-TCP deadline overflowed for timeout {value:?}")]
    DeadlineOverflow { value: Duration },
    #[error("DNS-over-TCP deadline expired during {phase} after {transferred} phase byte(s)")]
    Timeout { phase: Phase, transferred: usize },
    /// The TCP connection could not be established.
    ///
    /// `message` names the socket step; the system failure that step reported,
    /// when there was one, stays in `source` instead of being formatted into
    /// the message.
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
    /// The prefixed query could not be written completely.
    ///
    /// A socket refusal keeps its system failure in `source`; the module's own
    /// accounting invariants have no source and say so in `message` alone.
    #[error("DNS-over-TCP query write stopped after {written} of {expected} bytes: {message}")]
    Write {
        written: usize,
        expected: usize,
        message: String,
        #[source]
        source: Option<Source>,
    },
    /// A response read failed before an orderly end of stream.
    ///
    /// A socket refusal keeps its system failure in `source`; the module's own
    /// accounting invariants have no source and say so in `message` alone.
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
    /// The retry-relevant class of this failure.
    ///
    /// This is the single classifier: an exhaustive match, so a new variant is
    /// a compile error here instead of being silently reported as a caller
    /// request fault.
    #[must_use]
    pub const fn category(&self) -> Category {
        match self {
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

    /// Exact framed-query bytes written before this failure.
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
            Self::Unsupported { .. }
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

/// Receipt for one complete, exactly framed DNS-over-TCP response.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Response {
    /// Remote endpoint confirmed by the connected socket.
    pub peer_address: SocketAddr,
    /// Local socket selected by the operating system.
    pub local_address: SocketAddr,
    /// Wall-clock marker recorded after the complete query was written.
    pub sent_at: SystemTime,
    /// Wall-clock marker recorded after the declared body arrived.
    pub received_at: SystemTime,
    /// Monotonic duration for connect, write, and read together.
    pub elapsed: Duration,
    /// Monotonic duration from query-write completion through response receipt.
    pub latency: Duration,
    /// Exact number of prefix and query bytes written.
    pub bytes_written: usize,
    /// One exact DNS-over-TCP frame, including its two-byte prefix. Its length
    /// is the exact number of prefix and response bytes read.
    pub frame: Bytes,
}

/// Runs one bounded DNS-over-TCP exchange through the selected provider.
/// Writes one framed query and reads the first framed response. Subsequent
/// messages on the stream are outside this response.
pub fn exchange<P: Provider>(request: Request<'_>, provider: &P) -> Result<Response, Error> {
    exchange_with_clock(request, provider, Instant::now)
}

fn exchange_with_clock<P: Provider>(
    request: Request<'_>,
    connector: &P,
    now: impl Fn() -> Instant,
) -> Result<Response, Error> {
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
    let mut stream = connector
        .connect(
            request.endpoint,
            &packetcraftr_core::budget::Deadline::new(connect_timeout),
        )
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

fn map_connect_error(endpoint: SocketAddr, source: io::Error) -> Error {
    if is_timeout(&source) {
        Error::Timeout {
            phase: Phase::Connect,
            transferred: 0,
        }
    } else {
        Error::Connect {
            endpoint,
            message: "the socket could not be opened".to_owned(),
            source: Some(Source::new(source)),
        }
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
