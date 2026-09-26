// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Explicit providers for bounded TCP connections. Protocol framing belongs to
//! the caller; providers own the connection and its native resources.

mod connect;

use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::Arc;
use std::time::Duration;

use packetcraftr_core::budget::{Cancelled, Deadline, Interrupted};
use packetcraftr_core::error::{Classification, Classified, Kind};

/// Process-wide connections that may hold a worker or an open socket at
/// once: a named sub-limit of the native worker pool, published as its own
/// resource row. It equals
/// [`WORKER_CAPACITY`](crate::resources::WORKER_CAPACITY), so connects may
/// fill the whole pool while no capture or route work holds a slot; any such
/// work lowers what connects can be admitted.
pub const MAX_PENDING_CONNECTIONS: usize = crate::resources::WORKER_CAPACITY;

/// Why a bounded TCP connection could not be admitted, started, or
/// completed, including the provider's own socket failure.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The provider's socket call failed. Its [`io::ErrorKind`] says how: the
    /// peer refused, the attempt timed out, the destination was unreachable,
    /// or a local failure.
    #[error(transparent)]
    Socket(#[from] io::Error),
    #[error("could not inspect the connected {operation} endpoint")]
    Evidence {
        operation: &'static str,
        #[source]
        source: io::Error,
    },
    /// The caller's deadline allows a connection longer than one hour.
    #[error("TCP connect timeout must be nonzero and at most one hour")]
    Timeout,
    /// The caller's deadline was spent before the connection could start.
    #[error("live operation deadline expired while starting a TCP connection")]
    DeadlineExceeded,
    #[error("TCP connect admission reached its process-wide limit of {limit}")]
    Capacity { limit: usize },
    #[error("TCP connect worker could not start")]
    Spawn(#[source] io::Error),
    #[error("TCP connect worker stopped without an outcome")]
    Worker,
    #[error("TCP connect attempt was already completed")]
    Completed,
    /// The caller cancelled the connection before it started.
    #[error(transparent)]
    Cancelled(#[from] Cancelled),
}

impl Error {
    /// The failure a connection reports when its caller's deadline stopped it
    /// before it started.
    fn interrupted(interrupted: Interrupted) -> Self {
        match interrupted {
            Interrupted::Cancelled(cancelled) => cancelled.into(),
            _ => Self::DeadlineExceeded,
        }
    }
}

impl Classified for Error {
    fn classification(&self) -> Classification {
        match self {
            Self::Socket(_) => Classification::new(
                "io.tcp_connect",
                Kind::Io,
                Some("inspect the socket failure and the destination's reachability"),
            ),
            Self::Evidence { .. } => Classification::new(
                "io.tcp_connect_evidence",
                Kind::Io,
                Some("inspect the socket endpoint query failure"),
            ),
            Self::Cancelled(source) => source.classification(),
            Self::DeadlineExceeded => crate::Error::DeadlineExceeded {
                operation: "starting a TCP connection",
            }
            .classification(),
            Self::Timeout => Classification::new(
                "cli.tcp_connect_timeout",
                Kind::Usage,
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

/// A socket and its worker-pool permit. The socket closes before the permit.
pub struct Connection<S> {
    inner: S,
    _permit: crate::workers::Permit,
}
impl<S> Connection<S> {
    fn new(inner: S, permit: crate::workers::Permit) -> Self {
        Self {
            inner,
            _permit: permit,
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
    pub result: Result<Connection<S>, Error>,
}
/// Pollable bounded connect. Dropping it cancels unstarted work; running calls
/// retain admission until their provider and socket cleanup finish.
pub struct PendingConnect<S> {
    inner: connect::Pending<S>,
}
impl<S> PendingConnect<S> {
    /// Stops unstarted work and reports whether a provider call was admitted.
    pub fn cancel(&mut self) -> bool {
        self.inner.cancel()
    }

    pub fn poll(&mut self) -> Result<Option<ConnectOutcome<S>>, Error> {
        self.inner.poll()
    }
}
/// Starts `provider.connect` on the native worker pool, admitted under
/// [`MAX_PENDING_CONNECTIONS`]. The worker receives what the caller's
/// `deadline` still allows, and its cancellation signal.
pub fn start_connect<P>(
    provider: Arc<P>,
    endpoint: SocketAddr,
    deadline: &Deadline,
) -> Result<PendingConnect<P::Stream>, Error>
where
    P: Provider + 'static,
    P::Stream: 'static,
{
    connect::start(provider, endpoint, deadline).map(|inner| PendingConnect { inner })
}

/// A connected byte stream with endpoint evidence and per-call time bounds.
/// Streams are owned by one caller at a time but may move between threads.
pub trait Stream: Read + Write + Send {
    fn peer_addr(&self) -> io::Result<SocketAddr>;
    fn local_addr(&self) -> io::Result<SocketAddr>;
    fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()>;
    fn set_write_timeout(&self, timeout: Option<Duration>) -> io::Result<()>;
}

/// Opens the exact numeric endpoint before the caller's deadline, following
/// the [deadline convention](crate::deadline). A socket failure is
/// [`Error::Socket`]; a connection that cannot start reports
/// [`Error::DeadlineExceeded`] for a spent deadline and [`Error::Cancelled`]
/// for a cancelled one.
pub trait Provider: Send + Sync {
    type Stream: Stream;

    fn connect(&self, endpoint: SocketAddr, deadline: &Deadline) -> Result<Self::Stream, Error>;
}

/// Explicitly selects portable standard-library system TCP sockets.
/// Available independently of packet route/capture/injection features.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemProvider;

impl Provider for SystemProvider {
    type Stream = SystemStream;

    fn connect(&self, endpoint: SocketAddr, deadline: &Deadline) -> Result<Self::Stream, Error> {
        let timeout = crate::deadline::remaining(deadline).map_err(Error::interrupted)?;
        Ok(SystemStream(TcpStream::connect_timeout(
            &endpoint, timeout,
        )?))
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
