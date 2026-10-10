// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use bytes::Bytes;
use packetcraftr_core::budget::Deadline;

use crate::bounded::{Exchange, Outcome, retryable, timeout};

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
    let mut bytes_read = 0;
    let outcome = 'exchange: {
        while bytes_sent < request.len() {
            let wait = match timeout(deadline) {
                Ok(wait) => wait,
                Err(outcome) => break 'exchange outcome,
            };
            if let Err(source) = stream.set_write_timeout(Some(wait)) {
                break 'exchange Outcome::Failed(source);
            }
            if let Err(source) = deadline.enforce() {
                break 'exchange Outcome::interrupted(source);
            }
            match stream.write(&request[bytes_sent..]) {
                Ok(0) => {
                    break 'exchange Outcome::Failed(std::io::ErrorKind::WriteZero.into());
                }
                Ok(count) if count <= request.len() - bytes_sent => bytes_sent += count,
                Ok(_) => {
                    break 'exchange Outcome::Failed(std::io::Error::other(
                        "TCP provider reported an impossible write length",
                    ));
                }
                Err(source) if retryable(&source) => continue,
                Err(source) => break 'exchange Outcome::Failed(source),
            }
        }
        if !request.is_empty() {
            loop {
                let wait = match timeout(deadline) {
                    Ok(wait) => wait,
                    Err(outcome) => break 'exchange outcome,
                };
                if let Err(source) = stream.set_write_timeout(Some(wait)) {
                    break 'exchange Outcome::Failed(source);
                }
                if let Err(source) = deadline.enforce() {
                    break 'exchange Outcome::interrupted(source);
                }
                match stream.flush() {
                    Ok(()) => break,
                    Err(source) if retryable(&source) => continue,
                    Err(source) => break 'exchange Outcome::Failed(source),
                }
            }
        }
        loop {
            // Cancellation/deadline has priority even after a provider call.
            let wait = match timeout(deadline) {
                Ok(wait) => wait,
                Err(outcome) => break 'exchange outcome,
            };
            if complete(&response[..bytes_read]) {
                break 'exchange Outcome::Complete;
            }
            if bytes_read == max_response {
                break 'exchange Outcome::Truncated;
            }
            if let Err(source) = stream.set_read_timeout(Some(wait)) {
                break 'exchange Outcome::Failed(source);
            }
            if let Err(source) = deadline.enforce() {
                break 'exchange Outcome::interrupted(source);
            }
            match stream.read(&mut response[bytes_read..]) {
                Ok(0) => {
                    break 'exchange match deadline.enforce() {
                        Ok(()) => Outcome::Eof,
                        Err(source) => Outcome::interrupted(source),
                    };
                }
                Ok(count) if count <= max_response - bytes_read => bytes_read += count,
                Ok(_) => {
                    break 'exchange Outcome::Failed(std::io::Error::other(
                        "TCP provider reported an impossible read length",
                    ));
                }
                Err(source) if retryable(&source) => continue,
                Err(source) => break 'exchange Outcome::Failed(source),
            }
        }
    };
    response.truncate(bytes_read);
    Ok(Exchange {
        response: Bytes::from(response),
        bytes_sent,
        outcome,
    })
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::collections::VecDeque;
    use std::io::{self, Cursor, Read, Write};
    use std::net::SocketAddr;
    use std::time::Duration;

    use packetcraftr_core::budget::Cancellation;

    use super::*;

    struct Duplex {
        input: Cursor<Vec<u8>>,
        output: Vec<u8>,
        fail_write_after: Option<usize>,
        cancel_on_timeout: Option<(Cancellation, usize)>,
        timeout_calls: Cell<usize>,
        require_flush: bool,
        flush_errors: VecDeque<io::ErrorKind>,
        flushed: bool,
        flushes: usize,
        reads: usize,
    }

    impl Read for Duplex {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            assert!(
                !self.require_flush || self.flushed,
                "request is still buffered"
            );
            self.reads += 1;
            self.input.read(buffer)
        }
    }

    impl Write for Duplex {
        fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
            if self.fail_write_after == Some(self.output.len()) {
                return Err(io::ErrorKind::BrokenPipe.into());
            }
            let count = self.fail_write_after.map_or(buffer.len(), |limit| {
                buffer.len().min(limit - self.output.len())
            });
            self.output.extend_from_slice(&buffer[..count]);
            Ok(count)
        }
        fn flush(&mut self) -> io::Result<()> {
            self.flushes += 1;
            if let Some(kind) = self.flush_errors.pop_front() {
                return Err(kind.into());
            }
            self.flushed = true;
            Ok(())
        }
    }

    impl Stream for Duplex {
        fn peer_addr(&self) -> io::Result<SocketAddr> {
            Ok("127.0.0.1:80".parse().unwrap())
        }
        fn local_addr(&self) -> io::Result<SocketAddr> {
            Ok("127.0.0.1:12345".parse().unwrap())
        }
        fn set_read_timeout(&self, _: Option<Duration>) -> io::Result<()> {
            let calls = self.timeout_calls.get() + 1;
            self.timeout_calls.set(calls);
            if let Some((signal, at)) = &self.cancel_on_timeout
                && calls == *at
            {
                signal.cancel();
            }
            Ok(())
        }
        fn set_write_timeout(&self, _: Option<Duration>) -> io::Result<()> {
            self.set_read_timeout(None)
        }
    }

    fn duplex(input: &[u8]) -> Duplex {
        Duplex {
            input: Cursor::new(input.to_vec()),
            output: vec![],
            fail_write_after: None,
            cancel_on_timeout: None,
            timeout_calls: Cell::new(0),
            require_flush: false,
            flush_errors: VecDeque::new(),
            flushed: false,
            flushes: 0,
            reads: 0,
        }
    }

    #[test]
    fn buffered_requests_are_flushed_before_reading_and_retry_only_the_flush() {
        for errors in [
            VecDeque::new(),
            VecDeque::from([io::ErrorKind::Interrupted]),
        ] {
            let mut stream = duplex(b"response");
            stream.require_flush = true;
            let expected_flushes = errors.len() + 1;
            stream.flush_errors = errors;
            let report = exchange(
                &mut stream,
                b"request",
                32,
                &Deadline::new(Duration::from_secs(1)),
                |bytes| bytes == b"response",
            )
            .unwrap();
            assert!(matches!(report.outcome, Outcome::Complete));
            assert_eq!(stream.output, b"request");
            assert_eq!(report.bytes_sent, 7);
            assert_eq!(report.response.as_ref(), b"response");
            assert_eq!(stream.flushes, expected_flushes);
        }
    }

    #[test]
    fn flush_failure_retains_writes_and_prevents_reads() {
        let mut stream = duplex(b"response");
        stream.flush_errors.push_back(io::ErrorKind::BrokenPipe);
        let report = exchange(
            &mut stream,
            b"request",
            32,
            &Deadline::new(Duration::from_secs(1)),
            |_| false,
        )
        .unwrap();
        assert_eq!(report.bytes_sent, 7);
        assert_eq!(stream.reads, 0);
        assert!(report.response.is_empty());
        assert!(
            matches!(report.outcome, Outcome::Failed(source) if source.kind() == io::ErrorKind::BrokenPipe)
        );
    }

    #[test]
    fn cancellation_during_flush_timeout_configuration_prevents_flush_and_reads() {
        let signal = Cancellation::default();
        let deadline =
            Deadline::new(Duration::from_secs(1)).with_cancellation(Some(signal.clone()));
        let mut stream = duplex(b"response");
        stream.cancel_on_timeout = Some((signal, 2));
        let report = exchange(&mut stream, b"request", 32, &deadline, |_| false).unwrap();
        assert!(matches!(report.outcome, Outcome::Cancelled));
        assert_eq!(report.bytes_sent, 7);
        assert_eq!(stream.flushes, 0);
        assert_eq!(stream.reads, 0);
    }

    #[test]
    fn banner_collection_never_flushes_or_writes() {
        let mut stream = duplex(b"banner\n");
        stream.flush_errors.push_back(io::ErrorKind::BrokenPipe);
        let report = exchange(
            &mut stream,
            b"",
            32,
            &Deadline::new(Duration::from_secs(1)),
            |bytes| bytes.ends_with(b"\n"),
        )
        .unwrap();
        assert!(matches!(report.outcome, Outcome::Complete));
        assert!(stream.output.is_empty());
        assert_eq!(stream.flushes, 0);
    }

    #[test]
    fn retains_partial_write_before_failure() {
        let mut stream = duplex(b"response");
        stream.fail_write_after = Some(3);
        let report = exchange(
            &mut stream,
            b"request",
            32,
            &Deadline::new(Duration::from_secs(1)),
            |_| false,
        )
        .unwrap();
        assert_eq!(report.bytes_sent, 3);
        assert_eq!(stream.output, b"req");
        assert!(report.response.is_empty());
        assert!(
            matches!(report.outcome, Outcome::Failed(source) if source.kind() == io::ErrorKind::BrokenPipe)
        );
    }

    #[test]
    fn full_buffer_requires_protocol_completion() {
        let deadline = Deadline::new(Duration::from_secs(1));
        let report = exchange(&mut duplex(b"banner\nmore"), b"", 7, &deadline, |_| false).unwrap();
        assert_eq!(report.response.as_ref(), b"banner\n");
        assert!(matches!(report.outcome, Outcome::Truncated));
        let report = exchange(&mut duplex(b"banner\nmore"), b"", 7, &deadline, |bytes| {
            bytes.ends_with(b"\n")
        })
        .unwrap();
        assert!(matches!(report.outcome, Outcome::Complete));
    }

    #[test]
    fn cancellation_prevents_all_io() {
        let signal = Cancellation::default();
        signal.cancel();
        let deadline = Deadline::new(Duration::from_secs(1)).with_cancellation(Some(signal));
        let mut stream = duplex(b"response");
        let report = exchange(&mut stream, b"request", 32, &deadline, |_| false).unwrap();
        assert!(matches!(report.outcome, Outcome::Cancelled));
        assert!(stream.output.is_empty());
        assert_eq!(stream.input.position(), 0);
    }

    #[test]
    fn cancellation_at_provider_boundary_prevents_the_next_transfer() {
        for request in [b"".as_slice(), b"request".as_slice()] {
            let signal = Cancellation::default();
            let deadline =
                Deadline::new(Duration::from_secs(1)).with_cancellation(Some(signal.clone()));
            let mut stream = duplex(b"response");
            stream.cancel_on_timeout = Some((signal, 1));
            let report = exchange(&mut stream, request, 32, &deadline, |_| false).unwrap();
            assert!(matches!(report.outcome, Outcome::Cancelled));
            assert!(stream.output.is_empty());
            assert_eq!(stream.input.position(), 0);
        }
    }
}
