// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::io::{self, Read, Write};

use packetcraftr_core::budget::Deadline;

use super::{Direction, Error, Limits};

pub(super) struct Wire<S, A> {
    pub(super) inner: S,
    pub(super) deadline: Deadline,
    pub(super) bytes_sent: usize,
    pub(super) bytes_read: usize,
    pub(super) steps: usize,
    pub(super) limits: Limits,
    authorize_write: A,
}

impl<S, A> Wire<S, A> {
    pub(super) fn new(inner: S, limits: Limits, deadline: Deadline, authorize_write: A) -> Self {
        Self {
            inner,
            deadline,
            bytes_sent: 0,
            bytes_read: 0,
            steps: 0,
            limits,
            authorize_write,
        }
    }

    fn step(&mut self) -> Result<std::time::Duration, Error> {
        let wait = self.deadline.live_remaining()?;
        if self.steps == self.limits.max_steps {
            return Err(Error::StepLimit {
                limit: self.limits.max_steps,
            });
        }
        self.steps += 1;
        Ok(wait.min(crate::deadline::POLL_INTERVAL))
    }
}

impl<S: crate::tcp::Stream, A> Read for Wire<S, A> {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        let remaining = self.limits.max_wire_bytes_read - self.bytes_read;
        if remaining == 0 {
            return Err(Error::WireLimit {
                direction: Direction::Read,
                limit: self.limits.max_wire_bytes_read,
            }
            .into_io());
        }
        let capacity = remaining.min(bytes.len());
        let wait = self.step().map_err(Error::into_io)?;
        self.inner.set_read_timeout(Some(wait))?;
        self.deadline
            .enforce()
            .map_err(Error::from)
            .map_err(Error::into_io)?;
        let count = self.inner.read(&mut bytes[..capacity])?;
        if count > capacity {
            return Err(io::Error::other(
                "TLS provider reported an impossible read length",
            ));
        }
        self.bytes_read += count;
        Ok(count)
    }
}

impl<S, A> Write for Wire<S, A>
where
    S: crate::tcp::Stream,
    A: FnMut(&[u8]) -> io::Result<()> + Send,
{
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let remaining = self.limits.max_wire_bytes_sent - self.bytes_sent;
        if remaining == 0 {
            return Err(Error::WireLimit {
                direction: Direction::Sent,
                limit: self.limits.max_wire_bytes_sent,
            }
            .into_io());
        }
        let capacity = remaining.min(bytes.len());
        let wait = self.step().map_err(Error::into_io)?;
        self.inner.set_write_timeout(Some(wait))?;
        self.deadline
            .enforce()
            .map_err(Error::from)
            .map_err(Error::into_io)?;
        (self.authorize_write)(&bytes[..capacity])?;
        self.deadline
            .enforce()
            .map_err(Error::from)
            .map_err(Error::into_io)?;
        let count = self.inner.write(&bytes[..capacity])?;
        if count > capacity {
            return Err(io::Error::other(
                "TLS provider reported an impossible write length",
            ));
        }
        self.bytes_sent += count;
        Ok(count)
    }

    fn flush(&mut self) -> io::Result<()> {
        let wait = self.step().map_err(Error::into_io)?;
        self.inner.set_write_timeout(Some(wait))?;
        self.deadline
            .enforce()
            .map_err(Error::from)
            .map_err(Error::into_io)?;
        self.inner.flush()
    }
}
