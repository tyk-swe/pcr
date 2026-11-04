// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use bytes::Bytes;
use packetcraftr_core::budget::Deadline;

use crate::bounded::{Exchange, Outcome, prepare_transfer, retryable, timeout};

use super::{Error, Stream};

/// Writes and flushes exactly one request, retaining at most `max_response` reply bytes.
///
/// `complete` recognizes a complete application record without issuing further
/// reads. The caller authorizes the endpoint and the exact request first.
/// Timeout, cancellation, EOF and failures retain all completed I/O. A full
/// buffer is conservatively truncated unless `complete` recognizes the record.
pub fn exchange(
    stream: &mut impl Stream,
    request: &[u8],
    max_response: usize,
    deadline: &Deadline,
    complete: impl Fn(&[u8]) -> bool,
) -> Result<Exchange, Error> {
    if max_response == 0 || max_response > 65_535 || request.len() > 65_537 {
        return Err(Error::ExchangeLimit);
    }
    let mut response = vec![0; max_response];
    let mut bytes_sent = 0;
    let (bytes_read, outcome) = match write_request(stream, request, deadline, &mut bytes_sent) {
        Ok(()) => read_response(stream, &mut response, deadline, complete),
        Err(outcome) => (0, outcome),
    };
    response.truncate(bytes_read);
    Ok(Exchange {
        response: Bytes::from(response),
        bytes_sent,
        outcome,
    })
}

fn write_request(
    stream: &mut impl Stream,
    request: &[u8],
    deadline: &Deadline,
    bytes_sent: &mut usize,
) -> Result<(), Outcome> {
    while *bytes_sent < request.len() {
        prepare_transfer(deadline, |wait| stream.set_write_timeout(wait))?;
        match stream.write(&request[*bytes_sent..]) {
            Ok(0) => return Err(Outcome::Failed(std::io::ErrorKind::WriteZero.into())),
            Ok(count) if count <= request.len() - *bytes_sent => *bytes_sent += count,
            Ok(_) => {
                return Err(Outcome::Failed(std::io::Error::other(
                    "TCP provider reported an impossible write length",
                )));
            }
            Err(source) if retryable(&source) => continue,
            Err(source) => return Err(Outcome::Failed(source)),
        }
    }
    if request.is_empty() {
        return Ok(());
    }
    flush_request(stream, deadline)
}

fn flush_request(stream: &mut impl Stream, deadline: &Deadline) -> Result<(), Outcome> {
    loop {
        prepare_transfer(deadline, |wait| stream.set_write_timeout(wait))?;
        match stream.flush() {
            Ok(()) => return Ok(()),
            Err(source) if retryable(&source) => continue,
            Err(source) => return Err(Outcome::Failed(source)),
        }
    }
}

fn read_response(
    stream: &mut impl Stream,
    response: &mut [u8],
    deadline: &Deadline,
    complete: impl Fn(&[u8]) -> bool,
) -> (usize, Outcome) {
    let mut bytes_read = 0;
    let outcome = loop {
        // Cancellation/deadline has priority even after a provider call.
        let wait = match timeout(deadline) {
            Ok(wait) => wait,
            Err(outcome) => break outcome,
        };
        if complete(&response[..bytes_read]) {
            break Outcome::Complete;
        }
        if bytes_read == response.len() {
            break Outcome::Truncated;
        }
        if let Err(source) = stream.set_read_timeout(Some(wait)) {
            break Outcome::Failed(source);
        }
        if let Err(source) = deadline.enforce() {
            break Outcome::interrupted(source);
        }
        match stream.read(&mut response[bytes_read..]) {
            Ok(0) => {
                break match deadline.enforce() {
                    Ok(()) => Outcome::Eof,
                    Err(source) => Outcome::interrupted(source),
                };
            }
            Ok(count) if count <= response.len() - bytes_read => bytes_read += count,
            Ok(_) => {
                break Outcome::Failed(std::io::Error::other(
                    "TCP provider reported an impossible read length",
                ));
            }
            Err(source) if retryable(&source) => continue,
            Err(source) => break Outcome::Failed(source),
        }
    };
    (bytes_read, outcome)
}

#[cfg(test)]
mod tests {
    use super::exchange;
    use crate::{bounded::Outcome, tcp::Stream};
    use packetcraftr_core::budget::{Cancellation, Deadline};
    use std::{
        collections::VecDeque,
        io::{self, Read, Write},
        net::SocketAddr,
        time::Duration,
    };

    #[derive(Debug)]
    enum Step {
        Write(&'static [u8], Result<usize, io::ErrorKind>),
        Flush(Result<(), io::ErrorKind>),
        Read(Result<&'static [u8], io::ErrorKind>),
        CancelRead(&'static [u8]),
    }

    struct ScriptedStream {
        steps: VecDeque<Step>,
        cancellation: Cancellation,
    }

    impl ScriptedStream {
        fn new(steps: impl IntoIterator<Item = Step>) -> Self {
            Self {
                steps: steps.into_iter().collect(),
                cancellation: Cancellation::default(),
            }
        }

        fn deadline(&self) -> Deadline {
            Deadline::new(Duration::from_secs(30))
                .with_cancellation(Some(self.cancellation.clone()))
        }
    }

    impl Write for ScriptedStream {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            let Some(Step::Write(expected, result)) = self.steps.pop_front() else {
                panic!("unexpected write");
            };
            assert_eq!(bytes, expected);
            result.map_err(Into::into)
        }

        fn flush(&mut self) -> io::Result<()> {
            let Some(Step::Flush(result)) = self.steps.pop_front() else {
                panic!("unexpected flush");
            };
            result.map_err(Into::into)
        }
    }

    impl Read for ScriptedStream {
        fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
            let response = match self.steps.pop_front() {
                Some(Step::Read(result)) => result.map_err(io::Error::from)?,
                Some(Step::CancelRead(response)) => {
                    self.cancellation.cancel();
                    response
                }
                other => panic!("unexpected read with next step {other:?}"),
            };
            bytes[..response.len()].copy_from_slice(response);
            Ok(response.len())
        }
    }

    impl Stream for ScriptedStream {
        fn peer_addr(&self) -> io::Result<SocketAddr> {
            Ok(([192, 0, 2, 1], 80).into())
        }

        fn local_addr(&self) -> io::Result<SocketAddr> {
            Ok(([192, 0, 2, 2], 1234).into())
        }

        fn set_read_timeout(&self, _timeout: Option<Duration>) -> io::Result<()> {
            Ok(())
        }

        fn set_write_timeout(&self, _timeout: Option<Duration>) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn partial_transfers_and_retries_preserve_exact_request_and_response() {
        let mut stream = ScriptedStream::new([
            Step::Write(b"ping", Err(io::ErrorKind::Interrupted)),
            Step::Write(b"ping", Ok(2)),
            Step::Write(b"ng", Err(io::ErrorKind::WouldBlock)),
            Step::Write(b"ng", Ok(2)),
            Step::Flush(Err(io::ErrorKind::TimedOut)),
            Step::Flush(Ok(())),
            Step::Read(Err(io::ErrorKind::Interrupted)),
            Step::Read(Ok(b"po")),
            Step::Read(Err(io::ErrorKind::WouldBlock)),
            Step::Read(Ok(b"ng")),
        ]);
        let deadline = stream.deadline();
        let result =
            exchange(&mut stream, b"ping", 4, &deadline, |bytes| bytes == b"pong").unwrap();
        assert_eq!(result.bytes_sent, b"ping".len());
        assert_eq!(result.response.as_ref(), b"pong");
        assert!(matches!(result.outcome, Outcome::Complete));
        assert!(stream.steps.is_empty());
    }

    #[test]
    fn failures_retain_completed_io_and_stop_further_transfers() {
        for (steps, sent, response, error) in [
            (
                vec![
                    Step::Write(b"ping", Ok(2)),
                    Step::Write(b"ng", Err(io::ErrorKind::BrokenPipe)),
                ],
                2,
                b"".as_slice(),
                io::ErrorKind::BrokenPipe,
            ),
            (
                vec![Step::Write(b"ping", Ok(2)), Step::Write(b"ng", Ok(0))],
                2,
                b"".as_slice(),
                io::ErrorKind::WriteZero,
            ),
            (
                vec![
                    Step::Write(b"ping", Ok(4)),
                    Step::Flush(Err(io::ErrorKind::BrokenPipe)),
                ],
                4,
                b"".as_slice(),
                io::ErrorKind::BrokenPipe,
            ),
            (
                vec![
                    Step::Write(b"ping", Ok(4)),
                    Step::Flush(Ok(())),
                    Step::Read(Ok(b"po")),
                    Step::Read(Err(io::ErrorKind::ConnectionReset)),
                ],
                4,
                b"po".as_slice(),
                io::ErrorKind::ConnectionReset,
            ),
        ] {
            let mut stream = ScriptedStream::new(steps);
            let deadline = stream.deadline();
            let result = exchange(&mut stream, b"ping", 4, &deadline, |_| false).unwrap();
            assert_eq!(result.bytes_sent, sent);
            assert_eq!(result.response.as_ref(), response);
            assert!(matches!(result.outcome, Outcome::Failed(source) if source.kind() == error));
            assert!(stream.steps.is_empty());
        }
    }

    #[test]
    fn empty_requests_read_without_writing_or_flushing_and_retain_bytes_on_eof() {
        let mut stream = ScriptedStream::new([Step::Read(Ok(b"po")), Step::Read(Ok(b""))]);
        let deadline = stream.deadline();
        let result = exchange(&mut stream, b"", 4, &deadline, |_| false).unwrap();
        assert_eq!(result.bytes_sent, 0);
        assert_eq!(result.response.as_ref(), b"po");
        assert!(matches!(result.outcome, Outcome::Eof));
        assert!(stream.steps.is_empty());
    }

    #[test]
    fn full_unrecognized_response_is_truncated_without_reading_more() {
        let mut stream = ScriptedStream::new([Step::Read(Ok(b"pong"))]);
        let deadline = stream.deadline();
        let result = exchange(&mut stream, b"", 4, &deadline, |_| false).unwrap();
        assert_eq!(result.response.as_ref(), b"pong");
        assert!(matches!(result.outcome, Outcome::Truncated));
        assert!(stream.steps.is_empty());
    }

    #[test]
    fn cancellation_after_read_retains_bytes_and_precedes_completion_or_eof() {
        for response in [b"".as_slice(), b"po", b"pong"] {
            let mut stream = ScriptedStream::new([Step::CancelRead(response)]);
            let deadline = stream.deadline();
            let result =
                exchange(&mut stream, b"", 4, &deadline, |bytes| bytes == b"pong").unwrap();
            assert_eq!(result.response.as_ref(), response);
            assert!(matches!(result.outcome, Outcome::Cancelled));
            assert!(stream.steps.is_empty());
        }
    }

    #[test]
    fn expired_deadline_prevents_io_and_takes_priority_over_completion() {
        for request in [b"".as_slice(), b"ping"] {
            let mut stream = ScriptedStream::new([]);
            let result = exchange(
                &mut stream,
                request,
                4,
                &Deadline::new(Duration::ZERO),
                |_| true,
            )
            .unwrap();
            assert_eq!(result.bytes_sent, 0);
            assert!(result.response.is_empty());
            assert!(matches!(result.outcome, Outcome::TimedOut));
        }
    }
}
