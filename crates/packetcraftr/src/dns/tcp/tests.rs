// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only
#![allow(dead_code)]

use std::collections::VecDeque;
use std::io::{Cursor, Read, Write};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicBool, Ordering};
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
fn short_attempt_waits_for_connect_then_deadline() {
    let timeout = Duration::from_millis(20);
    assert!(timeout < POLL_INTERVAL);
    let provider = connector(vec![0, 1, 1]);
    let started = provider.stream.state.lock().unwrap().now;
    let connecting = Arc::new(AtomicBool::new(false));
    let waited = Arc::new(AtomicBool::new(false));
    let begin_connect = Arc::clone(&connecting);
    let wait_selected = Arc::clone(&waited);

    // Model fast completion when DNS awaits it; bypassing that wait exhausts
    // the logical attempt independently of when the real worker gets scheduled.
    let response = query_with_connect_wait(
        Request {
            timeout,
            ..request(b"q")
        },
        Arc::new(provider.clone()),
        || {
            if !connecting.load(Ordering::SeqCst) {
                started
            } else if waited.load(Ordering::SeqCst) {
                started + Duration::from_millis(1)
            } else {
                started + timeout
            }
        },
        move |remaining| {
            assert_eq!(remaining, timeout);
            begin_connect.store(true, Ordering::SeqCst);
            // The DNS attempt uses the logical 20ms clock above. Real worker
            // scheduling gets a separate finite watchdog, not an attempt budget.
            Deadline::new(Duration::from_secs(10))
        },
        move |pending, deadline| {
            wait_selected.store(true, Ordering::SeqCst);
            pending.wait(deadline)
        },
    )
    .expect("completion waiting preserves the short logical DNS attempt");

    assert!(waited.load(Ordering::SeqCst));
    assert_eq!(response.elapsed, Duration::from_millis(1));
    assert_eq!(response.frame.as_ref(), [0, 1, 1]);
    assert_eq!(response.bytes_written, 3);
    assert_eq!(provider.stream.state.lock().unwrap().output, [0, 1, b'q']);
}

#[test]
fn explicit_provider_endpoint_mismatch_cannot_write_query_bytes() {
    let mut provider = connector(vec![0, 1, 1]);
    provider.stream.peer = "127.0.0.2:53".parse().unwrap();
    let error = query(request(b"q"), Arc::new(provider.clone())).unwrap_err();
    assert!(matches!(error, Error::Connect { source: None, .. }));
    assert!(provider.stream.state.lock().unwrap().output.is_empty());
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
