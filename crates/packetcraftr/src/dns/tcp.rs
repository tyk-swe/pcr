// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Bounded DNS-over-TCP framing; callers authorize destinations and validate responses.

use packetcraftr_netio::tcp::{self, Provider, Stream};
use packetcraftr_netio::{bounded, deadline::POLL_INTERVAL};
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;
use std::time::{Duration, SystemTime};

use bytes::Bytes;
use packetcraftr_core::budget::{Cancellation, Deadline, Interrupted};
use packetcraftr_core::error::Source;

mod error;

pub use error::{Category, Error, Phase};

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
/// Streams must honor the timeouts they are given: each read and write wait is at most
/// [`POLL_INTERVAL`], and a timeout before the deadline is retried after re-checking cancellation.
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
    query_with_connect_wait(
        request,
        connector,
        now,
        Deadline::new,
        tcp::PendingConnect::wait,
    )
}

fn query_with_connect_wait<P>(
    request: Request<'_>,
    connector: Arc<P>,
    now: impl Fn() -> Instant,
    connect_deadline: impl FnOnce(Duration) -> Deadline,
    wait: impl FnOnce(
        &mut tcp::PendingConnect<P::Stream>,
        &Deadline,
    ) -> Result<Option<tcp::ConnectOutcome<P::Stream>>, tcp::Error>,
) -> Result<Response, Error>
where
    P: Provider<Stream: 'static> + 'static,
{
    let query_frame = query_frame(&request)?;
    let started = now();
    let deadline = started
        .checked_add(request.timeout)
        .ok_or(Error::DeadlineOverflow {
            value: request.timeout,
        })?;
    let (mut stream, peer_address, local_address) =
        connect(connector, &request, deadline, &now, connect_deadline, wait)?;

    let mut bytes_written = 0usize;
    write_exact(
        &mut stream,
        &query_frame,
        deadline,
        request.cancellation,
        query_frame.len(),
        &mut bytes_written,
        &now,
    )?;
    let sent = now();
    let sent_at = SystemTime::now();

    let frame = read_frame(
        &mut stream,
        deadline,
        request.cancellation,
        request.max_message_bytes,
        &now,
    )?;
    let received_at = SystemTime::now();
    let completed = now();
    if completed >= deadline {
        return Err(Error::Timeout {
            phase: Phase::ReadMessage,
            transferred: frame.len() - LENGTH_PREFIX_BYTES,
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

fn query_frame(request: &Request<'_>) -> Result<Vec<u8>, Error> {
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
    let mut frame = Vec::with_capacity(LENGTH_PREFIX_BYTES + request.query.len());
    frame.extend_from_slice(&query_length.to_be_bytes());
    frame.extend_from_slice(request.query);
    Ok(frame)
}

fn connect<P>(
    connector: Arc<P>,
    request: &Request<'_>,
    deadline: Instant,
    now: &impl Fn() -> Instant,
    connect_deadline: impl FnOnce(Duration) -> Deadline,
    wait: impl FnOnce(
        &mut tcp::PendingConnect<P::Stream>,
        &Deadline,
    ) -> Result<Option<tcp::ConnectOutcome<P::Stream>>, tcp::Error>,
) -> Result<(tcp::Connection<P::Stream>, SocketAddr, SocketAddr), Error>
where
    P: Provider<Stream: 'static> + 'static,
{
    let connect_timeout = remaining(deadline, now(), Phase::Connect, 0)?;
    let connect_deadline =
        connect_deadline(connect_timeout).with_cancellation(request.cancellation.cloned());
    let mut pending = tcp::start_connect(connector, request.endpoint, &connect_deadline)
        .map_err(|source| map_connect_error(request.endpoint, source))?;
    let outcome = wait(&mut pending, &connect_deadline)
        .map_err(|source| map_connect_error(request.endpoint, source))?;
    connect_deadline
        .live_remaining()
        .map_err(|interrupted| match interrupted {
            Interrupted::Cancelled(cancelled) => Error::Cancelled {
                phase: Phase::Connect,
                transferred: 0,
                cancelled,
            },
            _ => Error::Timeout {
                phase: Phase::Connect,
                transferred: 0,
            },
        })?;
    remaining(deadline, now(), Phase::Connect, 0)?;
    let stream = outcome
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
    if !bounded::same_peer(request.endpoint, peer_address) {
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
    Ok((stream, peer_address, local_address))
}

fn read_frame<S: Stream>(
    stream: &mut S,
    deadline: Instant,
    cancellation: Option<&Cancellation>,
    max_message_bytes: usize,
    now: &impl Fn() -> Instant,
) -> Result<Vec<u8>, Error> {
    let mut prefix = [0u8; LENGTH_PREFIX_BYTES];
    let prefix_read = read_exact(
        stream,
        &mut prefix,
        deadline,
        cancellation,
        Phase::ReadPrefix,
        now,
    )?;
    if prefix_read != LENGTH_PREFIX_BYTES {
        return Err(Error::IncompletePrefix {
            actual: prefix_read,
        });
    }
    let declared = usize::from(u16::from_be_bytes(prefix));
    if declared == 0 {
        return Err(Error::ZeroLength);
    }
    if declared > max_message_bytes {
        return Err(Error::MessageTooLarge {
            declared,
            maximum: max_message_bytes,
        });
    }

    let total = LENGTH_PREFIX_BYTES + declared;
    let mut frame = Vec::with_capacity(total);
    frame.extend_from_slice(&prefix);
    frame.resize(total, 0);
    let (_, message) = frame.split_at_mut(LENGTH_PREFIX_BYTES);
    let message_read = read_exact(
        stream,
        message,
        deadline,
        cancellation,
        Phase::ReadMessage,
        now,
    )?;
    if message_read != declared {
        return Err(Error::IncompleteMessage {
            declared,
            actual: message_read,
        });
    }
    Ok(frame)
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

fn next_wait(
    deadline: Instant,
    cancellation: Option<&Cancellation>,
    now: Instant,
    phase: Phase,
    transferred: usize,
) -> Result<Duration, Error> {
    if let Some(cancellation) = cancellation {
        cancellation.check().map_err(|cancelled| Error::Cancelled {
            phase,
            transferred,
            cancelled,
        })?;
    }
    remaining(deadline, now, phase, transferred).map(|remaining| remaining.min(POLL_INTERVAL))
}

fn map_connect_error(endpoint: SocketAddr, error: packetcraftr_netio::tcp::Error) -> Error {
    use packetcraftr_netio::tcp::Error as TcpError;

    let timeout = Error::Timeout {
        phase: Phase::Connect,
        transferred: 0,
    };
    let source = match error {
        TcpError::Cancelled(cancelled) => {
            return Error::Cancelled {
                phase: Phase::Connect,
                transferred: 0,
                cancelled,
            };
        }
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
    cancellation: Option<&Cancellation>,
    expected: usize,
    written: &mut usize,
    now: &impl Fn() -> Instant,
) -> Result<(), Error> {
    while !bytes.is_empty() {
        let timeout = next_wait(deadline, cancellation, now(), Phase::Write, *written)?;
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
            Err(source) if is_retryable(&source) => {}
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
    loop {
        let timeout = next_wait(deadline, cancellation, now(), Phase::Write, *written)?;
        stream
            .set_write_timeout(Some(timeout))
            .map_err(|source| Error::ConfigureTimeout {
                phase: Phase::Write,
                transferred: *written,
                source: Source::new(source),
            })?;
        match stream.flush() {
            Ok(()) => return Ok(()),
            Err(source) if is_retryable(&source) => {}
            Err(source) => {
                return Err(Error::Write {
                    written: *written,
                    expected,
                    message: "the socket flush failed".to_owned(),
                    source: Some(Source::new(source)),
                });
            }
        }
    }
}

fn read_exact<S: Stream>(
    stream: &mut S,
    bytes: &mut [u8],
    deadline: Instant,
    cancellation: Option<&Cancellation>,
    phase: Phase,
    now: &impl Fn() -> Instant,
) -> Result<usize, Error> {
    let mut read = 0usize;
    while read < bytes.len() {
        let timeout = next_wait(deadline, cancellation, now(), phase, read)?;
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
            Err(source) if is_retryable(&source) => {}
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

/// The wait loops retry these after re-checking cancellation and the deadline.
fn is_retryable(error: &io::Error) -> bool {
    error.kind() == io::ErrorKind::Interrupted || is_timeout(error)
}

fn is_timeout(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::io::{Cursor, Read, Write};
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    const QUERY: &[u8] =
        b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01";

    struct BufferedStream {
        pending: Vec<u8>,
        response: Option<Cursor<Vec<u8>>>,
        flush_errors: VecDeque<io::ErrorKind>,
        cancellation: Option<Cancellation>,
        reads: Arc<AtomicUsize>,
    }

    impl Read for BufferedStream {
        fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
            self.reads.fetch_add(1, Ordering::SeqCst);
            match &mut self.response {
                Some(response) => response.read(bytes),
                None => Err(io::ErrorKind::WouldBlock.into()),
            }
        }
    }

    impl Write for BufferedStream {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            let count = bytes.len().min(3);
            self.pending.extend_from_slice(&bytes[..count]);
            Ok(count)
        }

        fn flush(&mut self) -> io::Result<()> {
            if let Some(error) = self.flush_errors.pop_front() {
                if let Some(cancellation) = self.cancellation.take() {
                    cancellation.cancel();
                }
                return Err(error.into());
            }
            let mut response = std::mem::take(&mut self.pending);
            assert_eq!(&response[..2], &(QUERY.len() as u16).to_be_bytes());
            assert_eq!(&response[2..], QUERY);
            response[4] = 0x81;
            response[5] = 0x80;
            self.response = Some(Cursor::new(response));
            Ok(())
        }
    }

    impl Stream for BufferedStream {
        fn peer_addr(&self) -> io::Result<SocketAddr> {
            Ok(SocketAddr::from(([127, 0, 0, 1], 53)))
        }

        fn local_addr(&self) -> io::Result<SocketAddr> {
            Ok(SocketAddr::from(([127, 0, 0, 1], 12345)))
        }

        fn set_read_timeout(&self, _timeout: Option<Duration>) -> io::Result<()> {
            Ok(())
        }

        fn set_write_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
            assert!(timeout.is_some_and(|wait| !wait.is_zero() && wait <= POLL_INTERVAL));
            Ok(())
        }
    }

    struct BufferedProvider(Mutex<Option<BufferedStream>>);

    impl Provider for BufferedProvider {
        type Stream = BufferedStream;

        fn connect(
            &self,
            _endpoint: SocketAddr,
            _deadline: &Deadline,
        ) -> Result<Self::Stream, tcp::Error> {
            Ok(self.0.lock().unwrap().take().unwrap())
        }
    }

    fn buffered_query(
        flush_errors: VecDeque<io::ErrorKind>,
        cancellation: Option<&Cancellation>,
    ) -> (Result<Response, Error>, usize) {
        let reads = Arc::new(AtomicUsize::new(0));
        let provider = Arc::new(BufferedProvider(Mutex::new(Some(BufferedStream {
            pending: Vec::new(),
            response: None,
            flush_errors,
            cancellation: cancellation.cloned(),
            reads: reads.clone(),
        }))));
        let result = query(
            Request {
                endpoint: SocketAddr::from(([127, 0, 0, 1], 53)),
                query: QUERY,
                timeout: Duration::from_secs(2),
                cancellation,
                max_message_bytes: 512,
            },
            provider,
        );
        (result, reads.load(Ordering::SeqCst))
    }

    #[test]
    fn buffered_query_flushes_the_complete_request_before_reading() {
        for flush_errors in [
            VecDeque::new(),
            VecDeque::from([
                io::ErrorKind::Interrupted,
                io::ErrorKind::WouldBlock,
                io::ErrorKind::TimedOut,
            ]),
        ] {
            let (result, _) = buffered_query(flush_errors, None);
            let response = result.unwrap();
            let mut expected = vec![0, QUERY.len() as u8];
            expected.extend_from_slice(QUERY);
            expected[4] = 0x81;
            expected[5] = 0x80;
            assert_eq!(response.frame.as_ref(), expected);
            assert_eq!(response.bytes_written, QUERY.len() + LENGTH_PREFIX_BYTES);
        }
    }

    #[test]
    fn permanent_flush_failure_retains_written_bytes_without_reading() {
        let (result, reads) = buffered_query(VecDeque::from([io::ErrorKind::BrokenPipe]), None);
        let Error::Write {
            written,
            expected,
            source: Some(_),
            ..
        } = result.unwrap_err()
        else {
            panic!("expected a flush failure");
        };
        assert_eq!(written, QUERY.len() + LENGTH_PREFIX_BYTES);
        assert_eq!(expected, written);
        assert_eq!(reads, 0);
    }

    #[test]
    fn retrying_flush_observes_cancellation_without_reading() {
        let cancellation = Cancellation::default();
        let (result, reads) = buffered_query(
            VecDeque::from([io::ErrorKind::Interrupted]),
            Some(&cancellation),
        );
        assert!(matches!(
            result.unwrap_err(),
            Error::Cancelled {
                phase: Phase::Write,
                transferred,
                ..
            } if transferred == QUERY.len() + LENGTH_PREFIX_BYTES
        ));
        assert_eq!(reads, 0);
    }

    #[test]
    fn retrying_flush_stops_at_the_write_deadline() {
        let reads = Arc::new(AtomicUsize::new(0));
        let mut stream = BufferedStream {
            pending: Vec::new(),
            response: None,
            flush_errors: VecDeque::from(vec![io::ErrorKind::TimedOut; 200]),
            cancellation: None,
            reads: reads.clone(),
        };
        let started = Instant::now();
        let ticks = std::cell::Cell::new(0);
        let now = || {
            ticks.set(ticks.get() + 1);
            started + Duration::from_millis(ticks.get())
        };
        let mut frame = (QUERY.len() as u16).to_be_bytes().to_vec();
        frame.extend_from_slice(QUERY);
        let mut written = 0;
        let error = write_exact(
            &mut stream,
            &frame,
            started + Duration::from_millis(100),
            None,
            frame.len(),
            &mut written,
            &now,
        )
        .unwrap_err();
        assert!(matches!(
            error,
            Error::Timeout {
                phase: Phase::Write,
                transferred,
            } if transferred == frame.len()
        ));
        assert_eq!(stream.pending, frame);
        assert_eq!(written, frame.len());
        assert_eq!(reads.load(Ordering::SeqCst), 0);
    }
}
