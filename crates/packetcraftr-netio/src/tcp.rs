// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Explicit providers for bounded TCP connections. Protocol framing belongs to
//! the caller; providers own the connection and its native resources.

mod connect;
mod error;

use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::Arc;
use std::time::Duration;

use packetcraftr_core::budget::Deadline;

pub use error::Error;

/// Process-wide connections that may hold a worker or an open socket at
/// once: a named sub-limit of the native worker pool, published as its own
/// resource row. It equals
/// [`WORKER_CAPACITY`](crate::resources::WORKER_CAPACITY), so connects may
/// fill the whole pool while no capture or route work holds a slot; any such
/// work lowers what connects can be admitted.
pub const MAX_PENDING_CONNECTIONS: usize = crate::resources::WORKER_CAPACITY;

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

    /// Waits for completion, waking as soon as the worker publishes its outcome.
    /// Returns `None` if `deadline` expires or is cancelled while work is pending;
    /// completed work is returned even if the waiting deadline has ended.
    pub fn wait(&mut self, deadline: &Deadline) -> Result<Option<ConnectOutcome<S>>, Error> {
        self.inner.wait(deadline)
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
