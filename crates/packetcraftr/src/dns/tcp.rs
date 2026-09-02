// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Bounded DNS-over-TCP framing over portable system sockets.
//!
//! This module deliberately exposes a DNS-specific exchange rather than a
//! general stream-socket abstraction. Higher-level workflows remain
//! responsible for destination authorization and DNS response validation.
//! One exchange consumes the first declared response frame and then drops the
//! connection; later messages on the stream are outside that frame.

use std::error::Error as StdError;
use std::fmt;
use std::io::{self, Read, Write};
use std::net::SocketAddr;
use std::net::TcpStream;
use std::sync::Arc;
use std::time::Instant;
use std::time::{Duration, SystemTime};

use bytes::Bytes;
use packetcraftr_core::error::{Classification, Classified, Kind};
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
    /// Establishing the TCP connection.
    Connect,
    /// Writing the prefixed DNS query.
    Write,
    /// Reading the two-byte response prefix.
    ReadPrefix,
    /// Reading the declared response message.
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

/// The system failure a socket phase carries.
///
/// Shared rather than boxed so [`Error`] stays `Clone` while retaining
/// `io::Error`, which is not.
pub type SocketFault = Arc<dyn StdError + Send + Sync>;

/// Typed failures from one DNS-over-TCP exchange.
#[derive(Clone, Debug, ThisError)]
#[non_exhaustive]
pub enum Error {
    /// Native DNS-over-TCP execution is unavailable in this feature profile.
    #[error("DNS-over-TCP system I/O is unavailable: {message}")]
    Unsupported { message: String },
    /// No time remained for the exchange.
    #[error("DNS-over-TCP timeout {value:?} is invalid; it must be non-zero")]
    InvalidTimeout { value: Duration },
    /// DNS-over-TCP cannot frame an empty query message.
    #[error("DNS-over-TCP query must not be empty")]
    EmptyQuery,
    /// The local query cannot be represented by the two-byte wire prefix.
    #[error("DNS-over-TCP query is {actual} bytes; maximum is {maximum}")]
    QueryTooLarge { actual: usize, maximum: usize },
    /// The response bound is not representable by DNS-over-TCP framing.
    #[error("DNS-over-TCP message limit {value} is invalid; expected 1..={maximum}")]
    InvalidMessageLimit { value: usize, maximum: usize },
    /// The monotonic absolute deadline could not be represented.
    #[error("DNS-over-TCP deadline overflowed for timeout {value:?}")]
    DeadlineOverflow { value: Duration },
    /// The shared absolute deadline expired during a socket phase.
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
        source: Option<SocketFault>,
    },
    /// A per-call socket timeout could not be installed.
    #[error(
        "DNS-over-TCP could not configure the {phase} timeout after {transferred} phase byte(s)"
    )]
    ConfigureTimeout {
        phase: Phase,
        transferred: usize,
        #[source]
        source: SocketFault,
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
        source: Option<SocketFault>,
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
        source: Option<SocketFault>,
    },
    /// The peer closed before the complete two-byte prefix arrived.
    #[error("DNS-over-TCP response prefix ended after {actual} of 2 bytes")]
    IncompletePrefix { actual: usize },
    /// DNS-over-TCP does not admit an empty DNS message.
    #[error("DNS-over-TCP response declared a zero-length DNS message")]
    ZeroLength,
    /// The declared response length exceeded the caller's bound.
    #[error("DNS-over-TCP response declared {declared} bytes; maximum is {maximum}")]
    MessageTooLarge { declared: usize, maximum: usize },
    /// The peer closed before the declared response body arrived.
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

    /// Walked from the retained `#[source]` chain rather than hand-written.
    fn causes(&self) -> Vec<String> {
        packetcraftr_core::error::source_chain(self)
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

/// Runs one bounded DNS-over-TCP exchange over a portable system socket.
///
/// Connects, writes one framed query, and reads the first framed response; a
/// subsequent message on the same stream is not part of that response. Backed
/// by `std::net::TcpStream`.
pub fn exchange(request: Request<'_>) -> Result<Response, Error> {
    exchange_with_connector(request, &SystemConnector)
}

trait Stream: Read + Write {
    fn peer_addr(&self) -> io::Result<SocketAddr>;
    fn local_addr(&self) -> io::Result<SocketAddr>;
    fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()>;
    fn set_write_timeout(&self, timeout: Option<Duration>) -> io::Result<()>;
}

impl Stream for TcpStream {
    fn peer_addr(&self) -> io::Result<SocketAddr> {
        Self::peer_addr(self)
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Self::local_addr(self)
    }

    fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        Self::set_read_timeout(self, timeout)
    }

    fn set_write_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        Self::set_write_timeout(self, timeout)
    }
}

trait Connector {
    type Stream: Stream;

    fn connect(&self, endpoint: SocketAddr, timeout: Duration) -> io::Result<Self::Stream>;
}

struct SystemConnector;

impl Connector for SystemConnector {
    type Stream = TcpStream;

    fn connect(&self, endpoint: SocketAddr, timeout: Duration) -> io::Result<Self::Stream> {
        TcpStream::connect_timeout(&endpoint, timeout)
    }
}

fn exchange_with_connector<C: Connector>(
    request: Request<'_>,
    connector: &C,
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

    let started = Instant::now();
    let deadline = started
        .checked_add(request.timeout)
        .ok_or(Error::DeadlineOverflow {
            value: request.timeout,
        })?;
    let connect_timeout = remaining(deadline, Phase::Connect, 0)?;
    let mut stream = connector
        .connect(request.endpoint, connect_timeout)
        .map_err(|source| map_connect_error(request.endpoint, source))?;
    let peer_address = stream.peer_addr().map_err(|source| Error::Connect {
        endpoint: request.endpoint,
        message: "peer socket inspection failed".to_owned(),
        source: Some(Arc::new(source)),
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
        source: Some(Arc::new(source)),
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
    )?;
    let sent = Instant::now();
    let sent_at = SystemTime::now();

    let mut response_prefix = [0u8; LENGTH_PREFIX_BYTES];
    let prefix_read = read_exact(
        &mut stream,
        &mut response_prefix,
        deadline,
        Phase::ReadPrefix,
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
    let message_read = read_exact(&mut stream, &mut message, deadline, Phase::ReadMessage)?;
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
    let completed = Instant::now();
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

fn remaining(deadline: Instant, phase: Phase, transferred: usize) -> Result<Duration, Error> {
    deadline
        .checked_duration_since(Instant::now())
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
            source: Some(Arc::new(source)),
        }
    }
}

fn write_exact<S: Stream>(
    stream: &mut S,
    mut bytes: &[u8],
    deadline: Instant,
    expected: usize,
    written: &mut usize,
) -> Result<(), Error> {
    while !bytes.is_empty() {
        let timeout = remaining(deadline, Phase::Write, *written)?;
        stream
            .set_write_timeout(Some(timeout))
            .map_err(|source| Error::ConfigureTimeout {
                phase: Phase::Write,
                transferred: *written,
                source: Arc::new(source),
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
                    source: Some(Arc::new(source)),
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
) -> Result<usize, Error> {
    let mut read = 0usize;
    while read < bytes.len() {
        let timeout = remaining(deadline, phase, read)?;
        stream
            .set_read_timeout(Some(timeout))
            .map_err(|source| Error::ConfigureTimeout {
                phase,
                transferred: read,
                source: Arc::new(source),
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
                    source: Some(Arc::new(source)),
                });
            }
        }
    }
    let _ = remaining(deadline, phase, read)?;
    Ok(read)
}

fn is_timeout(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
    )
}

#[cfg(test)]
mod tests {
    #![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

    use std::collections::VecDeque;
    use std::io::Cursor;
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::Mutex;

    use super::*;

    /// Field-by-field equality for an error that retains a system source and
    /// so cannot derive `PartialEq`. `Debug` renders every field, the source
    /// included, so this compares strictly more than a derived `==` did.
    #[track_caller]
    fn assert_same_error(actual: &Error, expected: &Error) {
        assert_eq!(format!("{actual:?}"), format!("{expected:?}"));
    }

    const ENDPOINT: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 53);
    const LOCAL: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 49_152);

    #[derive(Clone)]
    struct ScriptedConnector {
        stream: ScriptedStream,
        connect_error: Option<io::ErrorKind>,
    }

    impl Connector for ScriptedConnector {
        type Stream = ScriptedStream;

        fn connect(&self, _endpoint: SocketAddr, _timeout: Duration) -> io::Result<Self::Stream> {
            if let Some(kind) = self.connect_error {
                return Err(io::Error::from(kind));
            }
            Ok(self.stream.clone())
        }
    }

    #[derive(Clone)]
    struct ScriptedStream {
        state: Arc<Mutex<ScriptedState>>,
    }

    struct ScriptedState {
        input: Cursor<Vec<u8>>,
        output: Vec<u8>,
        read_chunks: VecDeque<usize>,
        read_pacing: VecDeque<Pacing>,
        write_chunks: VecDeque<usize>,
        write_delays: VecDeque<Duration>,
        read_interrupts: usize,
        write_interrupts: usize,
        read_timeouts: Vec<Duration>,
        write_timeouts: Vec<Duration>,
        write_submissions: Vec<usize>,
    }

    impl ScriptedStream {
        fn new(input: Vec<u8>) -> Self {
            Self {
                state: Arc::new(Mutex::new(ScriptedState {
                    input: Cursor::new(input),
                    output: Vec::new(),
                    read_chunks: VecDeque::new(),
                    read_pacing: VecDeque::new(),
                    write_chunks: VecDeque::new(),
                    write_delays: VecDeque::new(),
                    read_interrupts: 0,
                    write_interrupts: 0,
                    read_timeouts: Vec::new(),
                    write_timeouts: Vec::new(),
                    write_submissions: Vec::new(),
                })),
            }
        }
    }

    /// How much of the caller's deadline a scripted read spends before it
    /// delivers bytes.
    #[derive(Clone, Copy, Debug)]
    enum Pacing {
        /// Deliver immediately.
        Prompt,
        /// Sleep past the whole budget the caller just set for this read, so
        /// the read always completes after the deadline no matter how long the
        /// preceding phases took. Reading the budget back off the stream is
        /// what makes the outcome independent of the wall clock: a fixed delay
        /// only outlasts a fixed timeout when the machine is not loaded.
        PastDeadline,
    }

    /// How far past the caller's budget a [`Pacing::PastDeadline`] read sleeps.
    const OVERRUN_MARGIN: Duration = Duration::from_millis(1);

    impl Read for ScriptedStream {
        fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
            let overrun = {
                let mut state = self.state.lock().unwrap();
                if state.read_interrupts != 0 {
                    state.read_interrupts -= 1;
                    return Err(io::Error::from(io::ErrorKind::Interrupted));
                }
                match state.read_pacing.pop_front() {
                    Some(Pacing::PastDeadline) => Some(
                        state
                            .read_timeouts
                            .last()
                            .copied()
                            .expect("a bounded read sets its timeout first")
                            + OVERRUN_MARGIN,
                    ),
                    Some(Pacing::Prompt) | None => None,
                }
            };
            if let Some(overrun) = overrun {
                std::thread::sleep(overrun);
            }
            let mut state = self.state.lock().unwrap();
            let limit = state.read_chunks.pop_front().unwrap_or(bytes.len());
            let length = bytes.len().min(limit);
            state.input.read(&mut bytes[..length])
        }
    }

    impl Write for ScriptedStream {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            let delay = self.state.lock().unwrap().write_delays.pop_front();
            if let Some(delay) = delay {
                std::thread::sleep(delay);
            }
            let mut state = self.state.lock().unwrap();
            if state.write_interrupts != 0 {
                state.write_interrupts -= 1;
                return Err(io::Error::from(io::ErrorKind::Interrupted));
            }
            state.write_submissions.push(bytes.len());
            let length = bytes
                .len()
                .min(state.write_chunks.pop_front().unwrap_or(bytes.len()));
            state.output.extend_from_slice(&bytes[..length]);
            Ok(length)
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl Stream for ScriptedStream {
        fn peer_addr(&self) -> io::Result<SocketAddr> {
            Ok(ENDPOINT)
        }

        fn local_addr(&self) -> io::Result<SocketAddr> {
            Ok(LOCAL)
        }

        fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
            self.state
                .lock()
                .unwrap()
                .read_timeouts
                .push(timeout.unwrap());
            Ok(())
        }

        fn set_write_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
            self.state
                .lock()
                .unwrap()
                .write_timeouts
                .push(timeout.unwrap());
            Ok(())
        }
    }

    fn connector(input: Vec<u8>) -> ScriptedConnector {
        ScriptedConnector {
            stream: ScriptedStream::new(input),
            connect_error: None,
        }
    }

    /// The budget a deadline-crossing test hands the exchange. Every phase
    /// before the scripted overrun is in-memory work, so this only has to
    /// outlast scheduler noise; the overrun itself sleeps the whole remaining
    /// budget, so it also bounds how long such a test takes.
    const SCRIPTED_TIMEOUT: Duration = Duration::from_millis(50);

    fn request(query: &[u8]) -> Request<'_> {
        Request {
            endpoint: ENDPOINT,
            query,
            timeout: Duration::from_secs(1),
            max_message_bytes: usize::from(u16::MAX),
        }
    }

    #[test]
    fn partial_and_interrupted_io_preserves_exact_frames() {
        let response_message = vec![0x12, 0x34, 0x80, 0, 0, 1, 0, 0, 0, 0, 0, 0];
        let mut input = u16::try_from(response_message.len())
            .unwrap()
            .to_be_bytes()
            .to_vec();
        input.extend_from_slice(&response_message);
        let connector = connector(input.clone());
        {
            let mut state = connector.stream.state.lock().unwrap();
            state.write_chunks.extend([1, 1, 2, 1, 64]);
            state.write_delays.push_back(Duration::from_millis(10));
            state.read_chunks.extend([1, 1, 2, 3, 64]);
            state.read_pacing.extend([Pacing::Prompt; 5]);
            state.write_interrupts = 1;
            state.read_interrupts = 1;
        }

        let response = exchange_with_connector(request(b"query"), &connector).unwrap();

        assert_eq!(response.local_address, LOCAL);
        assert_eq!(response.frame.as_ref(), input);
        assert_eq!(response.bytes_written, 7);
        assert_eq!(response.frame.len(), input.len());
        assert!(response.received_at >= response.sent_at);
        assert!(response.elapsed > response.latency);
        let state = connector.stream.state.lock().unwrap();
        assert_eq!(state.output, [0, 5, b'q', b'u', b'e', b'r', b'y']);
        assert_eq!(state.write_submissions.first(), Some(&7));
        assert!(state.read_timeouts.len() > 2);
        assert!(state.write_timeouts.len() > 2);
        assert!(
            state
                .read_timeouts
                .iter()
                .chain(&state.write_timeouts)
                .all(|timeout| *timeout <= Duration::from_secs(1))
        );
    }

    #[test]
    fn framing_failures_are_distinct_and_bounded_before_allocation() {
        for (input, maximum, expected) in [
            (Vec::new(), 512, Error::IncompletePrefix { actual: 0 }),
            (vec![0], 512, Error::IncompletePrefix { actual: 1 }),
            (vec![0, 0], 512, Error::ZeroLength),
            (
                vec![2, 0],
                511,
                Error::MessageTooLarge {
                    declared: 512,
                    maximum: 511,
                },
            ),
            (
                vec![0, 4, 1, 2],
                512,
                Error::IncompleteMessage {
                    declared: 4,
                    actual: 2,
                },
            ),
        ] {
            let connector = connector(input);
            let error = exchange_with_connector(
                Request {
                    max_message_bytes: maximum,
                    ..request(b"q")
                },
                &connector,
            )
            .unwrap_err();
            assert_same_error(&error, &expected);
            assert_eq!(error.category(), Category::Framing);
        }
    }

    #[test]
    fn one_exchange_returns_only_the_first_declared_response_frame() {
        let response = exchange_with_connector(request(b"q"), &connector(vec![0, 1, 1, 0, 1, 2]))
            .expect("the first complete response frame is sufficient");

        assert_eq!(response.frame.as_ref(), [0, 1, 1]);
    }

    #[test]
    fn final_successful_read_cannot_complete_after_the_deadline() {
        let connector = connector(vec![0, 1, 1]);
        connector
            .stream
            .state
            .lock()
            .unwrap()
            .read_pacing
            .extend([Pacing::Prompt, Pacing::PastDeadline]);

        let error = exchange_with_connector(
            Request {
                timeout: SCRIPTED_TIMEOUT,
                ..request(b"q")
            },
            &connector,
        )
        .expect_err("a late final read must not produce a successful receipt");

        assert_same_error(
            &error,
            &Error::Timeout {
                phase: Phase::ReadMessage,
                transferred: 1,
            },
        );
    }

    #[test]
    fn late_end_of_stream_is_a_timeout_not_a_framing_failure() {
        for (input, pacing, phase, transferred) in [
            (
                vec![0],
                vec![Pacing::Prompt, Pacing::PastDeadline],
                Phase::ReadPrefix,
                1,
            ),
            (
                vec![0, 4, 1, 2],
                vec![Pacing::Prompt, Pacing::Prompt, Pacing::PastDeadline],
                Phase::ReadMessage,
                2,
            ),
        ] {
            let connector = connector(input);
            connector
                .stream
                .state
                .lock()
                .unwrap()
                .read_pacing
                .extend(pacing);

            let error = exchange_with_connector(
                Request {
                    timeout: SCRIPTED_TIMEOUT,
                    ..request(b"q")
                },
                &connector,
            )
            .expect_err("a late end of stream must report the expired deadline");

            assert_same_error(&error, &Error::Timeout { phase, transferred });
        }
    }

    #[test]
    fn request_and_connect_failures_have_stable_categories() {
        assert!(matches!(
            exchange_with_connector(
                Request {
                    timeout: Duration::ZERO,
                    ..request(b"q")
                },
                &connector(Vec::new())
            ),
            Err(Error::InvalidTimeout { .. })
        ));
        assert_same_error(
            &exchange_with_connector(
                request(b""),
                &ScriptedConnector {
                    stream: ScriptedStream::new(Vec::new()),
                    connect_error: Some(io::ErrorKind::TimedOut),
                },
            )
            .expect_err("an empty query is refused before the socket opens"),
            &Error::EmptyQuery,
        );
        assert!(matches!(
            exchange_with_connector(
                Request {
                    max_message_bytes: 0,
                    ..request(b"q")
                },
                &connector(Vec::new())
            ),
            Err(Error::InvalidMessageLimit { .. })
        ));
        let error = exchange_with_connector(
            request(b"q"),
            &ScriptedConnector {
                stream: ScriptedStream::new(Vec::new()),
                connect_error: Some(io::ErrorKind::ConnectionRefused),
            },
        )
        .unwrap_err();
        assert!(matches!(error, Error::Connect { .. }));
        assert_eq!(error.category(), Category::Network);
    }

    #[test]
    fn write_zero_and_socket_timeouts_are_typed() {
        let zero = connector(Vec::new());
        zero.stream.state.lock().unwrap().write_chunks.push_back(0);
        assert!(matches!(
            exchange_with_connector(request(b"q"), &zero),
            Err(Error::Write {
                written: 0,
                expected: 3,
                ..
            })
        ));

        let error = exchange_with_connector(
            request(b"q"),
            &ScriptedConnector {
                stream: ScriptedStream::new(Vec::new()),
                connect_error: Some(io::ErrorKind::TimedOut),
            },
        )
        .unwrap_err();
        assert_same_error(
            &error,
            &Error::Timeout {
                phase: Phase::Connect,
                transferred: 0,
            },
        );
        assert_eq!(error.category(), Category::Timeout);
    }

    #[test]
    fn failures_report_exact_framed_query_progress() {
        let framed = 7;
        assert_eq!(
            Error::Timeout {
                phase: Phase::Write,
                transferred: 3,
            }
            .query_bytes_written(framed),
            3
        );
        assert_eq!(
            Error::IncompletePrefix { actual: 1 }.query_bytes_written(framed),
            framed
        );
        assert_eq!(
            Error::Connect {
                endpoint: ENDPOINT,
                message: "fixture".to_owned(),
                source: None,
            }
            .query_bytes_written(framed),
            0
        );
    }
}
