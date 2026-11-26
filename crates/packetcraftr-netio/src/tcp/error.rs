// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::io;

use packetcraftr_core::budget::{Cancelled, Interrupted};
use packetcraftr_core::error::{Classification, Classified, Kind};

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    #[error("TCP exchange requires 1..=65535 response bytes and at most 65537 request bytes")]
    ExchangeLimit,
    #[error(transparent)]
    Socket(#[from] io::Error),
    #[error("could not inspect the connected {operation} endpoint")]
    Evidence {
        operation: &'static str,
        #[source]
        source: io::Error,
    },
    #[error("TCP connect timeout must be nonzero and at most one hour")]
    Timeout,
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
    #[error(transparent)]
    Cancelled(#[from] Cancelled),
}

impl Error {
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
                crate::code::IoTcpConnect,
                Kind::Io,
                Some("inspect the socket failure and the destination's reachability"),
            ),
            Self::Evidence { .. } => Classification::new(
                crate::code::IoTcpConnectEvidence,
                Kind::Io,
                Some("inspect the socket endpoint query failure"),
            ),
            Self::Cancelled(source) => source.classification(),
            Self::DeadlineExceeded => crate::code::deadline_exceeded(),
            Self::ExchangeLimit => {
                Classification::new(crate::code::CliTcpExchangeLimit, Kind::Usage, None)
            }
            Self::Timeout => Classification::new(
                crate::code::CliTcpConnectTimeout,
                Kind::Usage,
                Some("choose a finite nonzero connection timeout"),
            ),
            Self::Capacity { .. } => Classification::new(
                crate::code::IoTcpConnectCapacity,
                Kind::Io,
                Some("wait for admitted connection cleanup or reduce concurrency"),
            ),
            Self::Spawn(_) | Self::Worker => Classification::new(
                crate::code::IoTcpConnectWorker,
                Kind::Io,
                Some("inspect local worker resources and retry"),
            ),
            Self::Completed => Classification::new(
                crate::code::InternalTcpConnectState,
                Kind::Internal,
                Some("consume each completed connection exactly once"),
            ),
        }
    }
}
