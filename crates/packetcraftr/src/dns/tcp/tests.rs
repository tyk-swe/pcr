// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::VecDeque;
use std::io::{Cursor, Read, Write};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex};

use super::*;

use packetcraftr_core::budget::Deadline;
use packetcraftr_netio::deadline::POLL_INTERVAL;

#[track_caller]
fn assert_same_error(actual: &Error, expected: &Error) {
    assert_eq!(format!("{actual:?}"), format!("{expected:?}"));
}

const ENDPOINT: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 53);
const LOCAL: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 49_152);

fn query_with_connector(
    request: Request<'_>,
    connector: &ScriptedConnector,
) -> Result<Response, Error> {
    query_with_clock(request, Arc::new(connector.clone()), || {
        connector.stream.state.lock().unwrap().now
    })
}

#[derive(Clone)]
struct ScriptedConnector {
    stream: ScriptedStream,
    connect_error: Option<io::ErrorKind>,
}

impl Provider for ScriptedConnector {
    type Stream = ScriptedStream;

    fn connect(
        &self,
        _endpoint: SocketAddr,
        _deadline: &Deadline,
    ) -> Result<Self::Stream, packetcraftr_netio::tcp::Error> {
        if let Some(kind) = self.connect_error {
            return Err(io::Error::from(kind).into());
        }
        Ok(self.stream.clone())
    }
}

#[derive(Clone)]
struct ScriptedStream {
    state: Arc<Mutex<ScriptedState>>,
    peer: SocketAddr,
}

struct ScriptedState {
    now: Instant,
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
    read_error: Option<io::ErrorKind>,
    write_error: Option<io::ErrorKind>,
    read_stalls_at_end: bool,
    write_window: Option<usize>,
    cancel_on_stall: Option<Cancellation>,
}

impl ScriptedState {
    fn stall(&mut self, timeout: Duration) -> io::Error {
        self.now += timeout;
        if let Some(signal) = &self.cancel_on_stall {
            signal.cancel();
        }
        io::Error::from(io::ErrorKind::WouldBlock)
    }
}

impl ScriptedStream {
    fn new(input: Vec<u8>) -> Self {
        Self {
            state: Arc::new(Mutex::new(ScriptedState {
                now: Instant::now(),
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
                read_error: None,
                write_error: None,
                read_stalls_at_end: false,
                write_window: None,
                cancel_on_stall: None,
            })),
            peer: ENDPOINT,
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum Pacing {
    Prompt,
    PastDeadline,
}

const OVERRUN_MARGIN: Duration = Duration::from_millis(1);

impl Read for ScriptedStream {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        let overrun = {
            let mut state = self.state.lock().unwrap();
            if let Some(kind) = state.read_error.take() {
                return Err(io::Error::from(kind));
            }
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
            self.state.lock().unwrap().now += overrun;
        }
        let mut state = self.state.lock().unwrap();
        let limit = state.read_chunks.pop_front().unwrap_or(bytes.len());
        let length = bytes.len().min(limit);
        let count = state.input.read(&mut bytes[..length])?;
        if count == 0 && state.read_stalls_at_end {
            let timeout = *state
                .read_timeouts
                .last()
                .expect("a bounded read sets its timeout first");
            return Err(state.stall(timeout));
        }
        Ok(count)
    }
}

impl Write for ScriptedStream {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let delay = self.state.lock().unwrap().write_delays.pop_front();
        if let Some(delay) = delay {
            self.state.lock().unwrap().now += delay;
        }
        let mut state = self.state.lock().unwrap();
        if let Some(kind) = state.write_error.take() {
            return Err(io::Error::from(kind));
        }
        if state.write_interrupts != 0 {
            state.write_interrupts -= 1;
            return Err(io::Error::from(io::ErrorKind::Interrupted));
        }
        let room = state.write_window.map_or(usize::MAX, |window| {
            window.saturating_sub(state.output.len())
        });
        if room == 0 {
            let timeout = *state
                .write_timeouts
                .last()
                .expect("a bounded write sets its timeout first");
            return Err(state.stall(timeout));
        }
        state.write_submissions.push(bytes.len());
        let length = bytes
            .len()
            .min(state.write_chunks.pop_front().unwrap_or(bytes.len()))
            .min(room);
        state.output.extend_from_slice(&bytes[..length]);
        Ok(length)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Stream for ScriptedStream {
    fn peer_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.peer)
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

const SCRIPTED_TIMEOUT: Duration = Duration::from_millis(10);
const _: () = assert!(SCRIPTED_TIMEOUT.as_millis() < POLL_INTERVAL.as_millis());

fn request(query: &[u8]) -> Request<'_> {
    Request {
        endpoint: ENDPOINT,
        query,
        timeout: Duration::from_secs(1),
        cancellation: None,
        max_message_bytes: usize::from(u16::MAX),
    }
}

#[test]
fn explicit_provider_endpoint_mismatch_cannot_write_query_bytes() {
    let mut provider = connector(vec![0, 1, 1]);
    provider.stream.peer = "127.0.0.2:53".parse().unwrap();
    let error = query(request(b"q"), Arc::new(provider.clone())).unwrap_err();
    assert!(matches!(error, Error::Connect { source: None, .. }));
    assert!(provider.stream.state.lock().unwrap().output.is_empty());
}

/// A silent peer per waiting phase: `(phase, response bytes, write window, phase bytes transferred)`.
fn stalled_peers() -> [(Phase, Vec<u8>, Option<usize>, usize); 4] {
    [
        (Phase::Write, Vec::new(), Some(0), 0),
        (Phase::Write, Vec::new(), Some(2), 2),
        (Phase::ReadPrefix, Vec::new(), None, 0),
        (Phase::ReadMessage, vec![0, 4, 1, 2], None, 2),
    ]
}

fn stalled_peer(phase: Phase, input: Vec<u8>, window: Option<usize>) -> ScriptedConnector {
    let provider = connector(input);
    {
        let mut state = provider.stream.state.lock().unwrap();
        state.write_window = window;
        state.read_stalls_at_end = phase != Phase::Write;
    }
    provider
}

#[test]
fn stalled_socket_waits_are_sliced_until_the_deadline_and_preserve_query_progress() {
    for (phase, input, window, transferred) in stalled_peers() {
        let provider = stalled_peer(phase, input, window);
        let started = provider.stream.state.lock().unwrap().now;

        let error = query_with_connector(request(b"q"), &provider).unwrap_err();

        assert_same_error(&error, &Error::Timeout { phase, transferred });
        assert_eq!(
            error.query_bytes_written(3),
            if phase == Phase::Write {
                transferred
            } else {
                3
            }
        );
        let state = provider.stream.state.lock().unwrap();
        let timeouts = if phase == Phase::Write {
            &state.write_timeouts
        } else {
            &state.read_timeouts
        };
        assert!(timeouts.iter().all(|timeout| *timeout <= POLL_INTERVAL));
        assert_eq!(state.now - started, Duration::from_secs(1));
    }
}

#[test]
fn a_socket_timeout_with_budget_left_is_retried_rather_than_reported() {
    let provider = connector(vec![0, 1, 1]);
    {
        let mut state = provider.stream.state.lock().unwrap();
        state.write_error = Some(io::ErrorKind::TimedOut);
        state.read_error = Some(io::ErrorKind::WouldBlock);
    }

    let response = query_with_connector(request(b"q"), &provider).unwrap();

    assert_eq!(response.frame.as_ref(), [0, 1, 1]);
    assert_eq!(response.bytes_written, 3);
    let state = provider.stream.state.lock().unwrap();
    assert_eq!(state.write_timeouts.len(), 2);
    assert!(state.read_timeouts.len() >= 2);
}

#[test]
fn socket_failures_keep_their_phase_progress_and_source() {
    let provider = connector(Vec::new());
    provider.stream.state.lock().unwrap().write_error = Some(io::ErrorKind::BrokenPipe);
    assert!(matches!(
        query_with_connector(request(b"q"), &provider),
        Err(Error::Write {
            written: 0,
            expected: 3,
            source: Some(_),
            ..
        })
    ));

    let provider = connector(Vec::new());
    provider.stream.state.lock().unwrap().read_error = Some(io::ErrorKind::ConnectionReset);
    assert!(matches!(
        query_with_connector(request(b"q"), &provider),
        Err(Error::Read {
            phase: Phase::ReadPrefix,
            source: Some(_),
            ..
        })
    ));
}

#[test]
fn cancellation_interrupts_a_stalled_socket_wait_within_one_poll_interval() {
    for (phase, input, window, transferred) in stalled_peers() {
        let signal = Cancellation::default();
        let provider = stalled_peer(phase, input, window);
        let started = {
            let mut state = provider.stream.state.lock().unwrap();
            state.cancel_on_stall = Some(signal.clone());
            state.now
        };

        let error = query_with_connector(
            Request {
                timeout: Duration::from_secs(3600),
                cancellation: Some(&signal),
                ..request(b"q")
            },
            &provider,
        )
        .unwrap_err();

        assert!(
            matches!(
                error,
                Error::Cancelled { phase: cancelled_in, transferred: progress, .. }
                    if cancelled_in == phase && progress == transferred
            ),
            "{error:?}"
        );
        assert_eq!(error.category(), Category::Cancelled);
        assert_eq!(
            error.query_bytes_written(3),
            if phase == Phase::Write {
                transferred
            } else {
                3
            }
        );
        let state = provider.stream.state.lock().unwrap();
        assert!(state.now - started <= POLL_INTERVAL);
    }
}

#[test]
fn cancellation_before_connect_completes_has_written_no_query_bytes() {
    let signal = Cancellation::default();
    signal.cancel();
    let provider = connector(vec![0, 1, 1]);

    let error = query_with_connector(
        Request {
            cancellation: Some(&signal),
            ..request(b"q")
        },
        &provider,
    )
    .unwrap_err();

    assert!(matches!(
        error,
        Error::Cancelled {
            phase: Phase::Connect,
            transferred: 0,
            ..
        }
    ));
    assert_eq!(error.category(), Category::Cancelled);
    assert_eq!(error.query_bytes_written(3), 0);
    assert!(provider.stream.state.lock().unwrap().output.is_empty());
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

    let response = query_with_connector(request(b"query"), &connector).unwrap();

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
            .all(|timeout| *timeout <= POLL_INTERVAL)
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
        let error = query_with_connector(
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
fn one_query_returns_only_the_first_declared_response_frame() {
    let response = query_with_connector(request(b"q"), &connector(vec![0, 1, 1, 0, 1, 2]))
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

    let error = query_with_connector(
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

        let error = query_with_connector(
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
        query_with_connector(
            Request {
                timeout: Duration::ZERO,
                ..request(b"q")
            },
            &connector(Vec::new())
        ),
        Err(Error::InvalidTimeout { .. })
    ));
    assert_same_error(
        &query_with_connector(
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
        query_with_connector(
            Request {
                max_message_bytes: 0,
                ..request(b"q")
            },
            &connector(Vec::new())
        ),
        Err(Error::InvalidMessageLimit { .. })
    ));
    let error = query_with_connector(
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
        query_with_connector(request(b"q"), &zero),
        Err(Error::Write {
            written: 0,
            expected: 3,
            ..
        })
    ));

    let error = query_with_connector(
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
