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
    let mut bytes_read = 0;
    let outcome = 'exchange: {
        while bytes_sent < request.len() {
            if let Err(outcome) = prepare_transfer(deadline, |wait| stream.set_write_timeout(wait))
            {
                break 'exchange outcome;
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
                if let Err(outcome) =
                    prepare_transfer(deadline, |wait| stream.set_write_timeout(wait))
                {
                    break 'exchange outcome;
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
