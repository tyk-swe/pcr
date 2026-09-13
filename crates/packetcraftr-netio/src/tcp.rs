// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Explicit providers for bounded TCP connections. Protocol framing belongs to
//! the caller; providers own the connection and its native resources.

use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::Arc;
use std::time::Duration;

/// Process-wide connections that may retain worker or socket resources.
pub const MAX_PENDING_CONNECTIONS: usize = 16;

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ConnectError {
    #[error("could not inspect the connected {operation} endpoint: {source}")]
    Evidence {
        operation: &'static str,
        #[source]
        source: io::Error,
    },
    #[error("TCP connect timeout must be nonzero and at most one hour")]
    Timeout,
    #[error("TCP connect admission reached its process-wide limit of {limit}")]
    Capacity { limit: usize },
    #[error("TCP connect worker could not start: {0}")]
    Spawn(#[source] io::Error),
    #[error("TCP connect worker stopped without an outcome")]
    Worker,
    #[error("TCP connect attempt was already completed")]
    Completed,
    #[error(transparent)]
    Cancelled(#[from] packetcraftr_core::budget::Cancelled),
}
impl packetcraftr_core::error::Classified for ConnectError {
    fn classification(&self) -> packetcraftr_core::error::Classification {
        use packetcraftr_core::error::{Classification, Kind};
        match self {
            Self::Evidence { .. } => Classification::new(
                "io.tcp_connect_evidence",
                Kind::Io,
                Some("inspect the socket endpoint query failure"),
            ),
            Self::Cancelled(source) => source.classification(),
            Self::Timeout => Classification::new(
                "cli.tcp_connect_timeout",
                Kind::Cli,
                Some("choose a finite nonzero connection timeout"),
            ),
            Self::Capacity { .. } => Classification::new(
                "io.tcp_connect_capacity",
                Kind::Io,
                Some("wait for admitted connection cleanup or reduce concurrency"),
            ),
            Self::Spawn(_) | Self::Worker => Classification::new(
                "io.tcp_connect_worker",
                Kind::Io,
                Some("inspect local worker resources and retry"),
            ),
            Self::Completed => Classification::new(
                "internal.tcp_connect_state",
                Kind::Internal,
                Some("consume each completed connection exactly once"),
            ),
        }
    }
}

/// A socket and its process-wide admission lease. The socket closes before the lease.
pub struct Connection<S> {
    inner: S,
    _lease: Arc<crate::platform::TcpConnectLease>,
}
impl<S> Connection<S> {
    pub(crate) fn new(inner: S, lease: Arc<crate::platform::TcpConnectLease>) -> Self {
        Self {
            inner,
            _lease: lease,
        }
    }
}
impl<S: Read> Read for Connection<S> {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        self.inner.read(bytes)
    }
}
impl<S: Write> Write for Connection<S> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.inner.write(bytes)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}
impl<S: Stream> Stream for Connection<S> {
    fn peer_addr(&self) -> io::Result<SocketAddr> {
        self.inner.peer_addr()
    }
    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }
    fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        self.inner.set_read_timeout(timeout)
    }
    fn set_write_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        self.inner.set_write_timeout(timeout)
    }
}

/// Exact socket-call outcome and its timing, without fabricated packet evidence.
pub struct ConnectOutcome<S> {
    /// Whether the provider was called, rather than expiring in the dispatch queue.
    pub attempted: bool,
    pub started_at: std::time::SystemTime,
    pub completed_at: std::time::SystemTime,
    pub elapsed: Duration,
    pub result: io::Result<Connection<S>>,
}
/// Pollable bounded connect. Dropping it cancels unstarted work; running calls
/// retain admission until their provider and socket cleanup finish.
pub struct PendingConnect<S> {
    inner: crate::platform::TcpConnectPending<S>,
}
impl<S> PendingConnect<S> {
    /// Stops unstarted work and reports whether a provider call was admitted.
    pub fn cancel(&mut self) -> bool {
        self.inner.cancel()
    }

    pub fn poll(&mut self) -> Result<Option<ConnectOutcome<S>>, ConnectError> {
        self.inner.poll()
    }
}
pub fn start_connect<P>(
    provider: Arc<P>,
    endpoint: SocketAddr,
    timeout: Duration,
    cancellation: Option<packetcraftr_core::budget::Cancellation>,
) -> Result<PendingConnect<P::Stream>, ConnectError>
where
    P: Provider + Send + Sync + 'static,
    P::Stream: Send + 'static,
{
    crate::platform::start_tcp_connect(provider, endpoint, timeout, cancellation)
        .map(|inner| PendingConnect { inner })
}

/// A connected byte stream with endpoint evidence and per-call time bounds.
pub trait Stream: Read + Write {
    fn peer_addr(&self) -> io::Result<SocketAddr>;
    fn local_addr(&self) -> io::Result<SocketAddr>;
    fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()>;
    fn set_write_timeout(&self, timeout: Option<Duration>) -> io::Result<()>;
}

/// Opens the exact numeric endpoint within the supplied nonzero time bound.
pub trait Provider {
    type Stream: Stream;

    fn connect(&self, endpoint: SocketAddr, timeout: Duration) -> io::Result<Self::Stream>;
}

/// Explicitly selects portable standard-library system TCP sockets.
/// Available independently of packet route/capture/injection features.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemProvider;

impl Provider for SystemProvider {
    type Stream = SystemStream;

    fn connect(&self, endpoint: SocketAddr, timeout: Duration) -> io::Result<Self::Stream> {
        TcpStream::connect_timeout(&endpoint, timeout).map(SystemStream)
    }
}

/// An owned native connection. Construction is through [`SystemProvider`].
pub struct SystemStream(pub(crate) TcpStream);

impl Read for SystemStream {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        self.0.read(bytes)
    }
}

impl Write for SystemStream {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.write(bytes)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.0.flush()
    }
}

impl Stream for SystemStream {
    fn peer_addr(&self) -> io::Result<SocketAddr> {
        self.0.peer_addr()
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.0.local_addr()
    }

    fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        self.0.set_read_timeout(timeout)
    }

    fn set_write_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        self.0.set_write_timeout(timeout)
    }
}
