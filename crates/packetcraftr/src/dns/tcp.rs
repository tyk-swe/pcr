// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Bounded DNS-over-TCP framing; callers authorize destinations and validate responses.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use bytes::Bytes;
use packetcraftr_core::budget::{Cancellation, Deadline, Interrupted};
use packetcraftr_core::clock::{Clock, SystemClock};
use packetcraftr_core::error::Source;
use packetcraftr_netio::bounded::Outcome;
use packetcraftr_netio::tcp::{self, Provider, Stream};

use crate::client::tcp::{ConnectError, connect as connect_tcp};

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
/// Streams must honor the timeouts they are given: each read and write wait is bounded by
/// `packetcraftr_netio::tcp::exchange`, retrying transient timeouts until the deadline.
pub fn query<P>(request: Request<'_>, provider: Arc<P>) -> Result<Response, Error>
where
    P: Provider<Stream: 'static> + 'static,
{
    query_with_clock(request, provider, &SystemClock)
}

/// [`query`] timed by `clock`.
pub(crate) fn query_with_clock<P, K: Clock>(
    request: Request<'_>,
    connector: Arc<P>,
    clock: &K,
) -> Result<Response, Error>
where
    P: Provider<Stream: 'static> + 'static,
{
    let query_frame = query_frame(&request)?;
    let started = clock.now();
    if started.checked_add(request.timeout).is_none() {
        return Err(Error::DeadlineOverflow {
            value: request.timeout,
        });
    }
    let time = clock.clone();
    let deadline = Deadline::with_time_source(request.timeout, move || time.now())
        .with_cancellation(request.cancellation.cloned());
    let connected = connect_tcp(connector, None, request.endpoint, &deadline)
        .map_err(|error| map_connect_error(request.endpoint, error))?;
    let mut stream = connected.stream;
    let peer_address = connected.peer;
    let local_address = connected.local;

    let bytes_written = write_frame(&mut stream, &query_frame, &deadline)?;
    let sent = clock.now();
    let sent_at = clock.wall_now();

    let frame = read_frame(&mut stream, &deadline, request.max_message_bytes)?;
    let received_at = clock.wall_now();
    let completed = clock.now();
    check_deadline(
        &deadline,
        Phase::ReadMessage,
        frame.len() - LENGTH_PREFIX_BYTES,
    )?;
    Ok(Response {
        peer_address,
        local_address,
        sent_at,
        received_at,
        elapsed: completed.saturating_duration_since(started),
        latency: completed.saturating_duration_since(sent),
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

fn check_deadline(deadline: &Deadline, phase: Phase, transferred: usize) -> Result<(), Error> {
    deadline
        .live_remaining()
        .map(|_| ())
        .map_err(|interrupted| match interrupted {
            Interrupted::Cancelled(cancelled) => Error::Cancelled {
                phase,
                transferred,
                cancelled,
            },
            _ => Error::Timeout { phase, transferred },
        })
}

fn cancelled_or_timeout(deadline: &Deadline, phase: Phase, transferred: usize) -> Error {
    match deadline.check_cancelled() {
        Err(cancelled) => Error::Cancelled {
            phase,
            transferred,
            cancelled,
        },
        Ok(()) => Error::Timeout { phase, transferred },
    }
}

fn write_frame<S: Stream>(
    stream: &mut S,
    frame: &[u8],
    deadline: &Deadline,
) -> Result<usize, Error> {
    let exchange =
        tcp::exchange(stream, frame, 1, deadline, |_| true).map_err(|source| Error::Write {
            written: 0,
            expected: frame.len(),
            message: "the socket write failed".to_owned(),
            source: Some(Source::new(source)),
        })?;
    match exchange.outcome {
        Outcome::Complete => Ok(exchange.bytes_sent),
        Outcome::Cancelled => Err(cancelled_or_timeout(
            deadline,
            Phase::Write,
            exchange.bytes_sent,
        )),
        Outcome::TimedOut => Err(Error::Timeout {
            phase: Phase::Write,
            transferred: exchange.bytes_sent,
        }),
        Outcome::Failed(source) => Err(Error::Write {
            written: exchange.bytes_sent,
            expected: frame.len(),
            message: if exchange.bytes_sent == frame.len() {
                "the socket flush failed".to_owned()
            } else {
                "the socket write failed".to_owned()
            },
            source: Some(Source::new(source)),
        }),
        Outcome::Eof | Outcome::Truncated => Err(Error::Write {
            written: exchange.bytes_sent,
            expected: frame.len(),
            message: "the socket write stopped unexpectedly".to_owned(),
            source: None,
        }),
    }
}

fn read_exact_bounded<S: Stream>(
    stream: &mut S,
    len: usize,
    deadline: &Deadline,
    phase: Phase,
) -> Result<(Bytes, bool), Error> {
    let exchange = tcp::exchange(stream, &[], len, deadline, |bytes| bytes.len() == len).map_err(
        |source| Error::Read {
            phase,
            message: "the socket read failed".to_owned(),
            source: Some(Source::new(source)),
        },
    )?;
    match exchange.outcome {
        Outcome::Complete | Outcome::Truncated => Ok((exchange.response, true)),
        Outcome::Eof => Ok((exchange.response, false)),
        Outcome::Cancelled => Err(cancelled_or_timeout(
            deadline,
            phase,
            exchange.response.len(),
        )),
        Outcome::TimedOut => Err(Error::Timeout {
            phase,
            transferred: exchange.response.len(),
        }),
        Outcome::Failed(source) => Err(Error::Read {
            phase,
            message: "the socket read failed".to_owned(),
            source: Some(Source::new(source)),
        }),
    }
}

fn read_frame<S: Stream>(
    stream: &mut S,
    deadline: &Deadline,
    max_message_bytes: usize,
) -> Result<Vec<u8>, Error> {
    let (prefix_bytes, complete) =
        read_exact_bounded(stream, LENGTH_PREFIX_BYTES, deadline, Phase::ReadPrefix)?;
    if !complete || prefix_bytes.len() != LENGTH_PREFIX_BYTES {
        return Err(Error::IncompletePrefix {
            actual: prefix_bytes.len(),
        });
    }
    let prefix = [prefix_bytes[0], prefix_bytes[1]];
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

    let (message_bytes, complete) =
        read_exact_bounded(stream, declared, deadline, Phase::ReadMessage)?;
    if !complete || message_bytes.len() != declared {
        return Err(Error::IncompleteMessage {
            declared,
            actual: message_bytes.len(),
        });
    }
    let mut frame = Vec::with_capacity(LENGTH_PREFIX_BYTES + declared);
    frame.extend_from_slice(&prefix);
    frame.extend_from_slice(&message_bytes);
    Ok(frame)
}

fn map_connect_error(endpoint: SocketAddr, error: ConnectError) -> Error {
    use packetcraftr_netio::tcp::Error as TcpError;

    let timeout = Error::Timeout {
        phase: Phase::Connect,
        transferred: 0,
    };
    match error {
        ConnectError::Policy(source) => Error::Connect {
            endpoint,
            message: "the destination is not authorized".to_owned(),
            source: Some(Source::new(source)),
        },
        ConnectError::PeerChanged { actual, .. } => Error::Connect {
            endpoint,
            message: format!("connected peer changed to {actual}"),
            source: None,
        },
        ConnectError::PeerAddr(source) => Error::Connect {
            endpoint,
            message: "peer socket inspection failed".to_owned(),
            source: Some(Source::new(source)),
        },
        ConnectError::LocalAddr(source) => Error::Connect {
            endpoint,
            message: "local socket inspection failed".to_owned(),
            source: Some(Source::new(source)),
        },
        ConnectError::Tcp(error) => {
            let source = match error {
                TcpError::Cancelled(cancelled) => {
                    return Error::Cancelled {
                        phase: Phase::Connect,
                        transferred: 0,
                        cancelled,
                    };
                }
                TcpError::Socket(source) if packetcraftr_netio::bounded::timed_out(&source) => {
                    return timeout;
                }
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
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use packetcraftr_netio::deadline::POLL_INTERVAL;
    use std::collections::VecDeque;
    use std::io::{self, Cursor, Read, Write};
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Instant;

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
            let Some(response) = &mut self.response else {
                return Err(io::ErrorKind::WouldBlock.into());
            };
            let count = response.read(bytes)?;
            if response.position() == response.get_ref().len() as u64
                && let Some(cancellation) = self.cancellation.take()
            {
                cancellation.cancel();
            }
            Ok(count)
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
    fn buffered_query_flushes_before_reading() {
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
    fn flush_failure_preserves_written_bytes() {
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
    fn cancelled_flush_prevents_reading() {
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
    fn cancellation_during_final_read_prevents_a_response() {
        let cancellation = Cancellation::default();
        let (result, _) = buffered_query(VecDeque::new(), Some(&cancellation));
        assert!(matches!(
            result.unwrap_err(),
            Error::Cancelled {
                phase: Phase::ReadMessage,
                transferred,
                ..
            } if transferred == QUERY.len()
        ));
    }

    #[test]
    fn cancellation_while_recording_the_response_preserves_message_bytes() {
        #[derive(Clone)]
        struct CancelOnReceive {
            reads: Arc<AtomicUsize>,
            cancellation: Cancellation,
        }

        impl Clock for CancelOnReceive {
            type Error = std::convert::Infallible;

            fn now(&self) -> Instant {
                SystemClock.now()
            }

            fn wall_now(&self) -> SystemTime {
                if self.reads.load(Ordering::SeqCst) > 0 {
                    self.cancellation.cancel();
                }
                SystemClock.wall_now()
            }

            fn sleep(&self, delay: Duration, deadline: &Deadline) -> Result<(), Self::Error> {
                SystemClock.sleep(delay, deadline)
            }
        }

        let clock = CancelOnReceive {
            reads: Arc::new(AtomicUsize::new(0)),
            cancellation: Cancellation::default(),
        };
        let provider = Arc::new(BufferedProvider(Mutex::new(Some(BufferedStream {
            pending: Vec::new(),
            response: None,
            flush_errors: VecDeque::new(),
            cancellation: None,
            reads: Arc::clone(&clock.reads),
        }))));
        let result = query_with_clock(
            Request {
                endpoint: SocketAddr::from(([127, 0, 0, 1], 53)),
                query: QUERY,
                timeout: Duration::from_secs(2),
                cancellation: Some(&clock.cancellation),
                max_message_bytes: 512,
            },
            provider,
            &clock,
        );
        assert!(matches!(
            result.unwrap_err(),
            Error::Cancelled {
                phase: Phase::ReadMessage,
                transferred,
                ..
            } if transferred == QUERY.len()
        ));
    }

    /// Advances one millisecond on every read.
    #[derive(Clone)]
    struct Ticking {
        started: Instant,
        ticks: Arc<AtomicUsize>,
    }

    impl Clock for Ticking {
        type Error = std::convert::Infallible;

        fn now(&self) -> Instant {
            let ticks = self.ticks.fetch_add(1, Ordering::SeqCst) + 1;
            self.started + Duration::from_millis(ticks as u64)
        }

        fn wall_now(&self) -> SystemTime {
            SystemTime::now()
        }

        fn sleep(&self, _: Duration, _: &Deadline) -> Result<(), Self::Error> {
            Ok(())
        }
    }

    #[test]
    fn the_given_clock_bounds_the_whole_query() {
        let provider = Arc::new(BufferedProvider(Mutex::new(Some(BufferedStream {
            pending: Vec::new(),
            response: None,
            flush_errors: VecDeque::new(),
            cancellation: None,
            reads: Arc::new(AtomicUsize::new(0)),
        }))));
        let clock = Ticking {
            started: SystemClock.now(),
            ticks: Arc::new(AtomicUsize::new(0)),
        };
        let error = query_with_clock(
            Request {
                endpoint: SocketAddr::from(([127, 0, 0, 1], 53)),
                query: QUERY,
                timeout: Duration::from_millis(1),
                cancellation: None,
                max_message_bytes: 512,
            },
            Arc::clone(&provider),
            &clock,
        )
        .unwrap_err();
        assert!(
            matches!(
                error,
                Error::Timeout {
                    phase: Phase::Connect,
                    transferred: 0
                }
            ),
            "{error:?}"
        );
        assert!(provider.0.lock().unwrap().is_some());
    }

    #[test]
    fn flush_retries_stop_at_deadline() {
        let reads = Arc::new(AtomicUsize::new(0));
        let mut stream = BufferedStream {
            pending: Vec::new(),
            response: None,
            flush_errors: VecDeque::from(vec![io::ErrorKind::TimedOut; 200]),
            cancellation: None,
            reads: reads.clone(),
        };
        let clock = Ticking {
            started: SystemClock.now(),
            ticks: Arc::new(AtomicUsize::new(0)),
        };
        let mut frame = (QUERY.len() as u16).to_be_bytes().to_vec();
        frame.extend_from_slice(QUERY);
        let time = clock.clone();
        let deadline = Deadline::with_time_source(Duration::from_millis(100), move || time.now());
        let error = write_frame(&mut stream, &frame, &deadline).unwrap_err();
        assert!(matches!(
            error,
            Error::Timeout {
                phase: Phase::Write,
                transferred,
            } if transferred == frame.len()
        ));
        assert_eq!(stream.pending, frame);
        assert_eq!(reads.load(Ordering::SeqCst), 0);
    }
}
