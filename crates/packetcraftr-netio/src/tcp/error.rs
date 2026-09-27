// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Why a bounded TCP connection could not be admitted, started, or completed.

use std::io;

use packetcraftr_core::budget::{Cancelled, Interrupted};
use packetcraftr_core::error::{Classification, Classified, Kind};

/// Why a bounded TCP connection could not be admitted, started, or
/// completed, including the provider's own socket failure.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The provider's socket call failed. Its [`io::ErrorKind`] says how: the
    /// peer refused, the attempt timed out, the destination was unreachable,
    /// or a local failure.
    #[error(transparent)]
    Socket(#[from] io::Error),
    #[error("could not inspect the connected {operation} endpoint")]
    Evidence {
        operation: &'static str,
        #[source]
        source: io::Error,
    },
    /// The caller's deadline allows a connection longer than
    /// [`deadline::MAX_WAIT`](crate::deadline::MAX_WAIT).
    #[error("TCP connect timeout must be nonzero and at most one hour")]
    Timeout,
    /// The caller's deadline was spent before the connection could start.
    #[error("live operation deadline expired while starting a TCP connection")]
    DeadlineExceeded,
    #[error("TCP connect admission reached its process-wide limit of {limit}")]
    Capacity { limit: usize },
    #[error("TCP connect worker could not start")]
    Spawn(#[source] io::Error),
    #[error("TCP connect worker stopped without an outcome")]
    Worker,
    #[error("TCP connect attempt was already completed")]
    Completed,
    /// The caller cancelled the connection before it started.
    #[error(transparent)]
    Cancelled(#[from] Cancelled),
}

impl Error {
    /// The failure a connection reports when its caller's deadline stopped it
    /// before it started.
    pub(super) fn interrupted(interrupted: Interrupted) -> Self {
        match interrupted {
            Interrupted::Cancelled(cancelled) => cancelled.into(),
            _ => Self::DeadlineExceeded,
        }
    }
}

impl Classified for Error {
    fn classification(&self) -> Classification {
        match self {
            Self::Socket(_) => Classification::new(
                "io.tcp_connect",
                Kind::Io,
                Some("inspect the socket failure and the destination's reachability"),
            ),
            Self::Evidence { .. } => Classification::new(
                "io.tcp_connect_evidence",
                Kind::Io,
                Some("inspect the socket endpoint query failure"),
            ),
            Self::Cancelled(source) => source.classification(),
            Self::DeadlineExceeded => crate::Error::DeadlineExceeded {
                operation: "starting a TCP connection",
            }
            .classification(),
            Self::Timeout => Classification::new(
                "cli.tcp_connect_timeout",
                Kind::Usage,
                Some("choose a finite nonzero connection timeout"),
            ),
            Self::Capacity { .. } => Classification::new(
                "io.tcp_connect_capacity",
                Kind::Io,
                Some("wait for admitted connection cleanup or reduce concurrency"),
            ),
            Self::Spawn(_) | Self::Worker => Classification::new(
                "io.tcp_connect_worker",
                Kind::Io,
                Some("inspect local worker resources and retry"),
            ),
            Self::Completed => Classification::new(
                "internal.tcp_connect_state",
                Kind::Internal,
                Some("consume each completed connection exactly once"),
            ),
        }
    }
}
