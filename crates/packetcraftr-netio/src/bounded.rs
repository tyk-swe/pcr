// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Evidence from bounded application I/O, including partial transfers.

use std::io;

use bytes::Bytes;
use packetcraftr_core::budget::{Deadline, Interrupted};

/// Application bytes transferred before the exchange stopped.
#[derive(Debug)]
pub struct Exchange {
    pub response: Bytes,
    pub bytes_sent: usize,
    pub outcome: Outcome,
}

#[derive(Debug)]
pub enum Outcome {
    Complete,
    Eof,
    /// The receive boundary was reached; no additional bytes were read.
    Truncated,
    TimedOut,
    Cancelled,
    Failed(io::Error),
}

impl Outcome {
    pub(crate) fn interrupted(source: Interrupted) -> Self {
        match source {
            Interrupted::Cancelled(_) => Self::Cancelled,
            _ => Self::TimedOut,
        }
    }
}

pub(crate) fn timeout(deadline: &Deadline) -> Result<std::time::Duration, Outcome> {
    crate::deadline::remaining(deadline)
        .map(|remaining| remaining.min(crate::deadline::POLL_INTERVAL))
        .map_err(Outcome::interrupted)
}

pub(crate) fn retryable(source: &io::Error) -> bool {
    matches!(
        source.kind(),
        io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
    )
}
